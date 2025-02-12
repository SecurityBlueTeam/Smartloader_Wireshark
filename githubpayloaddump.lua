Encryption = require("Smartloader_Encryption")

local info = {
	version = "Alpha",
	author = "BADMAN",
	description = "extract, decode and dump smartloader payloads to disk",
	repository = "a harddrive somewhere"
}

--set a log file
local userDesktop = os.getenv("USERPROFILE") .. "\\Desktop\\"
local log_file = io.open(userDesktop .. "log.txt", "a")
-- url check strings, most payloads hosted from user-attachments github repo can add more here
local urlsstrings_to_check = {"/user-attachments/files/"}

-- check if known malicous key words are in url - currently only searching for user-attachments GH repo
local function check_url_for_keywords(url)
	
	for _, keyword in ipairs(urlsstrings_to_check) do
		local start, finish = string.find(url, keyword,0,true)
		if start then
			return true
		end
	end
	return false
end

-- do a get request to identified malicious repo and write file to SmartloaderPayloads folder on users desktop
local function get_payload(strurl)

	local payloadfile = string.match(strurl, "/files/(%d+)/(.+)") .. ".smartloader"
	os.execute("powershell.exe mkdir $env:USERPROFILE\\Desktop\\SmartLoaderPayloads")
	os.execute("powershell.exe wget https://github.com/" .. strurl .. " -outfile $env:USERPROFILE\\Desktop\\SmartLoaderPayloads\\" .. payloadfile )
	log_file:write("\nretrieved payload: " .. payloadfile)
	log_file:flush()
	return payloadfile
end

-- decode, decrypt and write 
local function decrypt_payload(payloadfile)
	
	local payloadpath = userDesktop .. "SmartLoaderPayloads\\" .. payloadfile
	log_file:write("\ndecrypting payload at: " .. payloadpath .. "\n")
	log_file:flush()
	local file = io.open(payloadpath, "r")
	local content = file:read("*l")
	local ciphertext = Encryption.unhex(content)
	local key_table = Encryption.parse_key_string(Smartloader.prefs.key)
        local cleartext_table = Encryption.decrypt(key_table, ciphertext)
	cleartext = {}
		for i=1, #cleartext_table do
		table.insert(cleartext, string.char(cleartext_table[i]))
	end
	log_file:write("\ndecrypted payload: " .. table.concat(cleartext))
	log_file:flush()
	local decryptedfile = io.open(payloadpath .. ".decrypted", "wb")
	decryptedfile:write(table.concat(cleartext))
	decryptedfile:close()
	log_file:write("\ndecrypted payload written to file: " .. payloadfile .. ".decrypted\n")
	log_file:flush()
	
end

-- set up and run a http tap to introspect http requests to github
local f_host = Field.new("http.host")
local tcp_dstport = Field.new("tcp.dstport")
local f_url = Field.new("http.request.uri")
-- register a tap 
local tap = Listener.new("http")


function tap.packet(pinfo, tvb, tapinfo)

	-- check the dest port is 80
	local dst_port = tcp_dstport() and tonumber(tostring(tcp_dstport())) or 0
	local host = f_host() and tostring(f_host()) or "N/A"
	local url = f_url()
	if dst_port == 80 then
		if host == "github.com" then
			local strurl = tostring(url)
			log_file:flush()
				if check_url_for_keywords(strurl) then
				log_file:write("\nfound malicous repo: " .. strurl .. "\n")
				log_file:flush()
				local payloadfile = get_payload(strurl)
				log_file:flush()
				decrypt_payload(payloadfile)

			end
		end
	end

end

function tap.reset()
	print("tap reset")
end
