-- Unhex function
function unhex(input)
	retval = {}
	-- Split by comma
	for hex in string.gmatch(input, "([^,]+),") do
		--debug(string.format("Inserting: %x", tonumber(hex,16)))
		table.insert(retval, tonumber(hex,16))
	end
	return retval
end

-- Decryption routine
-- key is table of numbers {42, 223, 123}
-- ciphertext is table of numbers {42, 223, 123}
-- returns a table of numbers
function decrypt(key, ciphertext)
	plaintext = {}
	key_index = 1
	-- No key = nop
	if #key == 0 then
		return table.concat(ciphertext)
	end
	for i=1, #ciphertext do
		-- Decrypt
		plain_char = ciphertext[i] - key[key_index]
		if plain_char < 0 then
			plain_char = plain_char + 256
		end

		table.insert(plaintext, plain_char)

		--Update key index
		key_index = key_index + 1

		-- Roll key round if reaches length
		if key_index > #key then
			key_index = 1
		end
	end
	return plaintext
end

-- Encryption routine
-- key is table of numbers {42, 223, 123}
-- ciphertext is table of numbers {42, 223, 123}
-- returns a table of numbers
function encrypt(key, plaintext)
	ciphertext = {}
	key_index = 1
	-- No key = nop
	if #key == 0 then
		return table.concat(ciphertext)
	end
	for i=1, #plaintext do
		-- Decrypt
		cipher_char = plaintext[i] - key[key_index]
		if cipher_char > 255 then
			cipher_char = cipher_char - 256
		end

		table.insert(ciphertext, cipher_char)

		--Update key index
		key_index = key_index + 1

		-- Roll key round if reaches length
		if key_index > #key then
			key_index = 1
		end
	end
	return ciphertext
end

-- Take a plaintext key and return key object
function parse_key_string(text)
    output = {}
	strlen = #text
	for i=1,strlen do
		table.insert(output, string.byte(string.sub(text,i,i)))
	end
	return output
end

Encryption = {}
Encryption.decrypt = decrypt
Encryption.encrypt = encrypt
Encryption.unhex = unhex
Encryption.parse_key_string = parse_key_string

return Encryption
