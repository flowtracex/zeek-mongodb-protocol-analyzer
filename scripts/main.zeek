module MongoDB;

@load base/protocols/conn/removal-hooks

export {
	redef enum Log::ID += { LOG };

	const ports = { 27017/tcp } &redef;

	type Info: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		request_id: count &log &optional;
		response_to: count &log &optional;
		opcode: string &log;
		is_request: bool &log;
		is_reply: bool &log;
		database: string &log &optional;
		collection: string &log &optional;
		command: string &log &optional;
		crud_op: string &log &optional;
		ok: bool &log &optional;
		errmsg: string &log &optional;
		n: count &log &optional;
		n_modified: count &log &optional;
	};

	global log_policy: Log::PolicyHook;
	global log_mongodb: event(rec: Info);
	global finalize_mongodb: Conn::RemovalHook;

	global message: event(c: connection, is_orig: bool, message_length: count,
	                      request_id: count, response_to: count, opcode: count,
	                      payload_length: count, payload: string);
}

type PendingRequest: record {
	opcode: string;
	database: string &optional;
	collection: string &optional;
	command: string &optional;
	crud_op: string &optional;
};

type State: record {
	pending: table[count] of PendingRequest;
	violation: bool &default=F;
};

redef record connection += {
	mongodb_state: State &optional;
};

redef likely_server_ports += { ports };

function ensure_state(c: connection)
	{
	if ( ! c?$mongodb_state )
		{
		local s: State;
		c$mongodb_state = s;
		Conn::register_removal_hook(c, finalize_mongodb);
		}
	}

function reset_state(c: connection, weird_name: string, addl: string)
	{
	ensure_state(c);
	c$mongodb_state$violation = T;

	if ( addl != "" )
		Reporter::conn_weird(weird_name, c, addl);
	else
		Reporter::conn_weird(weird_name, c);

	delete c$mongodb_state;
	}

function le_u32(buf: string, offset: count): count
	{
	local b0 = bytestring_to_count(sub_bytes(buf, offset + 1, 1));
	local b1 = bytestring_to_count(sub_bytes(buf, offset + 2, 1));
	local b2 = bytestring_to_count(sub_bytes(buf, offset + 3, 1));
	local b3 = bytestring_to_count(sub_bytes(buf, offset + 4, 1));
	return b0 + b1 * 256 + b2 * 65536 + b3 * 16777216;
	}

function slice(buf: string, offset: count, n: count): string
	{
	return sub_bytes(buf, offset + 1, n);
	}

function bson_find_cstring_end(buf: string, offset: count): int
	{
	return find_str(buf, "\x00", offset);
	}

function crud_op_for(command: string): string
	{
	local c = to_lower(command);
	if ( c == "insert" )
		return "create";
	if ( c == "find" || c == "getmore" || c == "aggregate" || c == "count" || c == "distinct" )
		return "read";
	if ( c == "update" || c == "findandmodify" )
		return "update";
	if ( c == "delete" )
		return "delete";
	return "";
	}

function make_info(c: connection, opcode: string, is_request: bool): Info
	{
	return [$ts=network_time(), $uid=c$uid, $id=c$id, $opcode=opcode,
	        $is_request=is_request, $is_reply=!is_request];
	}

function op_name(opcode_num: count): string
	{
	if ( opcode_num == 2013 )
		return "OP_MSG";
	if ( opcode_num == 2012 )
		return "OP_COMPRESSED";
	return fmt("OP_%d", opcode_num);
	}

function parse_bson_doc(doc: string, want_request_fields: bool): table[string] of string
	{
	local out: table[string] of string;

	if ( |doc| < 5 )
		return out;

	local doc_len = le_u32(doc, 0);
	if ( doc_len > |doc| || doc_len < 5 )
		return out;

	local pos: count = 4;
	local end: count = doc_len - 1;
	local command_found = F;

	while ( pos < end )
		{
		local ty = slice(doc, pos, 1);
		pos += 1;

		local key_end = bson_find_cstring_end(doc, pos);
		if ( key_end < 0 )
			break;

		local key = slice(doc, pos, int_to_count(key_end) - pos);
		pos = int_to_count(key_end) + 1;

		if ( ty == "\x02" )
			{
			if ( pos + 4 > |doc| )
				break;

			local str_len = le_u32(doc, pos);
			if ( str_len == 0 || pos + 4 + str_len > |doc| )
				break;

			local str_value = slice(doc, pos + 4, str_len - 1);

			if ( key == "$db" )
				out["database"] = str_value;
			else if ( key == "errmsg" )
				out["errmsg"] = str_value;

			if ( want_request_fields && ! command_found && key != "$db" )
				{
				out["command"] = key;
				out["collection"] = str_value;
				local request_crud = crud_op_for(key);
				if ( request_crud != "" )
					out["crud_op"] = request_crud;
				command_found = T;
				}

			pos += 4 + str_len;
			}
		else if ( ty == "\x08" )
			{
			if ( pos + 1 > |doc| )
				break;

			if ( key == "ok" )
				out["ok"] = slice(doc, pos, 1) == "\x00" ? "F" : "T";

			pos += 1;
			}
		else if ( ty == "\x10" )
			{
			if ( pos + 4 > |doc| )
				break;

			local int_value = fmt("%d", le_u32(doc, pos));
			if ( key == "ok" )
				out["ok"] = int_value == "0" ? "F" : "T";
			else if ( key == "n" )
				out["n"] = int_value;
			else if ( key == "nModified" )
				out["n_modified"] = int_value;

			if ( want_request_fields && ! command_found && key != "$db" )
				{
				out["command"] = key;
				local request_int_crud = crud_op_for(key);
				if ( request_int_crud != "" )
					out["crud_op"] = request_int_crud;
				command_found = T;
				}

			pos += 4;
			}
		else if ( ty == "\x12" || ty == "\x09" || ty == "\x11" )
			{
			if ( pos + 8 > |doc| )
				break;
			pos += 8;
			}
		else if ( ty == "\x0A" )
			{
			# null
			}
		else if ( ty == "\x07" )
			{
			if ( pos + 12 > |doc| )
				break;
			pos += 12;
			}
		else if ( ty == "\x05" )
			{
			if ( pos + 5 > |doc| )
				break;
			local bin_len = le_u32(doc, pos);
			if ( pos + 5 + bin_len > |doc| )
				break;
			pos += 5 + bin_len;
			}
		else if ( ty == "\x03" || ty == "\x04" )
			{
			if ( pos + 4 > |doc| )
				break;
			local nested_len = le_u32(doc, pos);
			if ( nested_len < 5 || pos + nested_len > |doc| )
				break;
			pos += nested_len;
			}
		else if ( ty == "\x01" )
			{
			if ( pos + 8 > |doc| )
				break;
			pos += 8;
			}
		else
			{
			break;
			}
		}

	return out;
	}

function log_opaque_message(c: connection, request_id: count, response_to: count,
                            opcode: string, is_request: bool)
	{
	local rec = make_info(c, opcode, is_request);
	rec$request_id = request_id;

	if ( ! is_request )
		rec$response_to = response_to;

	if ( is_request )
		{
		local opaque_pending: PendingRequest = [$opcode=opcode];
		c$mongodb_state$pending[request_id] = opaque_pending;
		}
	else if ( response_to in c$mongodb_state$pending )
		{
		local reply_pending = c$mongodb_state$pending[response_to];
		rec$opcode = reply_pending$opcode;
		delete c$mongodb_state$pending[response_to];
		}

	Log::write(MongoDB::LOG, rec);
	}

function log_request(c: connection, request_id: count, opcode: string, parsed: table[string] of string)
	{
	local rec = make_info(c, opcode, T);
	rec$request_id = request_id;

	if ( "database" in parsed )
		rec$database = parsed["database"];
	if ( "collection" in parsed && parsed["collection"] != "" )
		rec$collection = parsed["collection"];
	if ( "command" in parsed )
		rec$command = parsed["command"];
	if ( "crud_op" in parsed && parsed["crud_op"] != "" )
		rec$crud_op = parsed["crud_op"];

	local pending: PendingRequest = [$opcode=opcode];
	if ( rec?$database )
		pending$database = rec$database;
	if ( rec?$collection )
		pending$collection = rec$collection;
	if ( rec?$command )
		pending$command = rec$command;
	if ( rec?$crud_op )
		pending$crud_op = rec$crud_op;

	c$mongodb_state$pending[request_id] = pending;
	Log::write(MongoDB::LOG, rec);
	}

function log_reply(c: connection, request_id: count, response_to: count, opcode: string,
                   parsed: table[string] of string)
	{
	local rec = make_info(c, opcode, F);
	rec$request_id = request_id;
	rec$response_to = response_to;

	if ( "ok" in parsed )
		rec$ok = parsed["ok"] == "T";
	if ( "errmsg" in parsed )
		rec$errmsg = parsed["errmsg"];
	if ( "n" in parsed )
		rec$n = to_count(parsed["n"]);
	if ( "n_modified" in parsed )
		rec$n_modified = to_count(parsed["n_modified"]);

	if ( response_to in c$mongodb_state$pending )
		{
		local pending = c$mongodb_state$pending[response_to];
		rec$opcode = pending$opcode;
		if ( pending?$database )
			rec$database = pending$database;
		if ( pending?$collection )
			rec$collection = pending$collection;
		if ( pending?$command )
			rec$command = pending$command;
		if ( pending?$crud_op )
			rec$crud_op = pending$crud_op;
		delete c$mongodb_state$pending[response_to];
		}

	Log::write(MongoDB::LOG, rec);
	}

function parse_op_msg_body(c: connection, is_orig: bool, request_id: count, response_to: count,
                           opcode: string, body: string): bool
	{
	if ( |body| < 5 )
		return F;

	local pos: count = 4;
	while ( pos < |body| )
		{
		local kind = slice(body, pos, 1);
		pos += 1;

		if ( kind == "\x00" )
			{
			if ( pos + 4 > |body| )
				return F;

			local doc_len = le_u32(body, pos);
			if ( doc_len < 5 || pos + doc_len > |body| )
				return F;

			local doc = slice(body, pos, doc_len);
			local parsed = parse_bson_doc(doc, is_orig);

			if ( is_orig )
				log_request(c, request_id, opcode, parsed);
			else
				log_reply(c, request_id, response_to, opcode, parsed);

			return T;
			}
		else if ( kind == "\x01" )
			{
			if ( pos + 4 > |body| )
				return F;
			local section_len = le_u32(body, pos);
			if ( section_len < 5 || pos + section_len > |body| )
				return F;
			pos += section_len;
			}
		else
			{
			return F;
			}
		}

	return F;
	}

event zeek_init() &priority=5
	{
	Log::create_stream(MongoDB::LOG,
		Log::Stream($columns=Info, $ev=log_mongodb, $path="mongodb", $policy=log_policy));

	Analyzer::register_for_ports(Analyzer::ANALYZER_MONGODB, ports);
	}

event MongoDB::message(c: connection, is_orig: bool, message_length: count,
                       request_id: count, response_to: count, opcode: count,
                       payload_length: count, payload: string)
	{
	if ( c$id$resp_p !in ports )
		return;

	if ( |payload| != payload_length )
		{
		reset_state(c, "mongodb_spicy_payload_length_mismatch",
		            fmt("%d != %d", |payload|, payload_length));
		return;
		}

	ensure_state(c);

	local opcode_name = op_name(opcode);

	if ( opcode == 2013 )
		{
		if ( ! parse_op_msg_body(c, is_orig, request_id, response_to, opcode_name, payload) )
			reset_state(c, "MongoDB_malformed_op_msg",
			            fmt("%s %d", is_orig ? "orig" : "resp", message_length));
		}
	else
		log_opaque_message(c, request_id, response_to, opcode_name, is_orig);
	}

hook finalize_mongodb(c: connection)
	{
	if ( c?$mongodb_state && c$mongodb_state$violation )
		return;

	if ( c?$mongodb_state )
		delete c$mongodb_state;
	}
