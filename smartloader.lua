Encryption = require("Smartloader_Encryption")
Base64 = require("base64")
json = require("json")

Smartloader = Proto("Smartloader", "Smartloader C2 protocol")

local info = {
	version = "1.0",
	author = "David Elliott",
	description = "Dissector for the smartloader C2 communications",
	repository = "a harddrive somewhere"
}

Smartloader.prefs.enabled = Pref.bool("Enable Dissector", true, "Enable or disable the dissector.")
Smartloader.prefs.key = Pref.string("C2 Encryption Key", "89pCO1NlLRkTZgb8DtZmKwC42AQcUeXF", "Encryption key used by strain")

set_plugin_info(info)

-- Define fields
local f_session_id = ProtoField.string("smartloader.session_id", "Session ID")
local f_payload = ProtoField.string("smartloader.payload", "Collected Data")
local f_http_file = Field.new("http.file_data")
local f_http_method = Field.new("http.request.method")
local f_req_uri     = Field.new("http.request.uri")
local f_res_code    = Field.new("http.response.code")
local f_tcp_fin		= Field.new("tcp.flags.fin")

Smartloader.fields = { f_session_id, f_payload }

function Smartloader:init()
	smartloader_sessions = {}
end

local function decrypt_req(str)
	-- Split out contents
	-- {"data": "akjdlkajda"}
	-- Need to extract from 3rd quote to 4th quote
	encryption_key = Encryption.parse_key_string(Smartloader.prefs.key)
	data = string.match(str, '{"data": ?"(.*)"}')
	hex = Base64.decode(data)
	bytes = Encryption.unhex(hex)
	decrypted = Encryption.decrypt(encryption_key, bytes)
	output = {}
	for i=1, #decrypted do
		table.insert(output, string.char(decrypted[i]))
	end
	return table.concat(output)
end

local function build_json_tree(tree, tvb,input_json)
	for k,v in pairs(input_json) do
		if type(v) == "table" then
			local current_tree = tree:add(Smartloader,tvb(),k)
			build_json_tree(current_tree, tvb, v)
		else
			tree:add(Smartloader,tvb(),k .. ": " .. tostring(v))
		end
	end
end

local function build_tree(tree, tvb,input)
	-- input looks like this   a=123&b=akljasd&c=askjasd
	for block in string.gmatch(input, "([^&]+)") do
		items = string.gmatch(block, "([^=]+)")
		tree:add(Smartloader,tvb(),items() .. ": " .. items())
	end
end

local function decrypt_res(str)
	local outputs = {}

	-- Parse Loader
	local output_loader = {}
	local loader = string.match(str, '{"loader": ?"(.+)",')
	loader_hex = Base64.decode(loader)
	loader_bytes = Encryption.unhex(loader_hex)
	loader_text = Encryption.decrypt(encryption_key, loader_bytes)
	for i=1, #loader_text do
		table.insert(output_loader, string.char(loader_text[i]))
	end
	outputs.loader = json.decode(table.concat(output_loader))

	-- Parse Tasks
	local output_tasks = {}
	local tasks = string.match(str,'"tasks":"(.+)"')
	local task_hex = Base64.decode(tasks)
	local task_bytes = Encryption.unhex(task_hex)
	local task_text = Encryption.decrypt(encryption_key,task_bytes)
	for i = 1, #task_text do
		table.insert(output_tasks, string.char(task_text[i]))
	end
	outputs.tasks = json.decode(table.concat(output_tasks))

	return outputs
end


local sessions = {}

local function hex_decode(hex)
	return (hex:gsub("%x%x", function(digits) return string.char(tonumber(digits, 16)) end))
end

local function get_session(pinfo)

	-- if being checked then dest->src
	key = string.format("%s:%i-%s:%i",
		tostring(pinfo.dst), pinfo.dst_port,
		tostring(pinfo.src), pinfo.src_port)
	return key
end

local function create_session(pinfo)
	-- If it is being created then src->dest
	key = string.format("%s:%i-%s:%i",
		tostring(pinfo.src), pinfo.src_port,
		tostring(pinfo.dst), pinfo.dst_port)
	return key
end

function Smartloader.dissector(tvb,pinfo,tree)
	local is_smartloader = false
	local session = ""
	-- Extract contents to Lua
	body = tvb:raw(0,tvb:len())

	status = f_res_code()
	if status then
		-- This is a response
		session = get_session(pinfo)
		if sessions[session] then
			is_smartloader = true
			sessions[session].responses = {}

			if f_http_file() then
				res_text = hex_decode(tostring(f_http_file().value))
				table.insert(sessions[session].responses, decrypt_res(res_text))
			end
		end
	else
		-- Identify request method
		method = f_http_method()
		uri = f_req_uri()
		if method == nil then
			-- This isn't HTTP
			return
		end
		-- Check if it is calling the correct APIs
		if method.value == "PUT" then
			if string.find(uri.value, "/api/") then
				is_smartloader = true
			elseif string.find(uri.value, "/task/") then
				is_smartloader = true
			end
		end
		if is_smartloader then
			session = create_session(pinfo)
			if sessions[session] then
				-- This is another request in the conversation
			else
				-- New session
				sessions[session] = {
					key = session,
					requests = {}
					} -- Create empty session
				-- Do we have data to Add?
				if f_http_file() then
					req_text = hex_decode(tostring(f_http_file().value))
					table.insert(sessions[session].requests, decrypt_req(req_text))
				end
			end
		end
	end

	-- Ensure we are smartloader
	if is_smartloader == false then
		return
	end

	-- Set up tree output
	pinfo.cols.protocol = Smartloader.name
	local subtree = tree:add(Smartloader,tvb(),"Smartloader")
	local requests_tree = subtree:add(Smartloader, tvb(), "Requests")
	local response_tree = subtree:add(Smartloader, tvb(), "Responses")

	-- get current_session

	-- Parse requests
	if not sessions[session] then
		return
	end
	for i=1, #sessions[session].requests do
		local req_i = requests_tree:add(Smartloader,tvb(), i)
		build_tree(req_i,tvb, sessions[session].requests[i])
	end

	for i=1, #sessions[session].responses do
		local res_i = response_tree:add(Smartloader,tvb(),i)
		outputs = sessions[session].responses[i]
		build_json_tree(res_i,tvb, sessions[session].responses[i])
	end

	-- Cleanup Finished Sessions
	-- Check for fin flag
	if f_tcp_fin().value == true then
		sessions[session] = nil
	end

end

register_postdissector(Smartloader)
