const crypto = require("crypto");

const REGEX_HEX = /^([a-fA-F0-9][a-fA-F0-9])+$/;
const REGEX_BASE64 = /^([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)?$/;

module.exports = class CryptoProvider {
	static DEFAULT_ENCODING = "utf8";

	static SYMMETRIC_ALGORITHM = {
		aes: "aes"
	};
	static SYMMETRIC_ALGORITHM_DEFAULT = this.SYMMETRIC_ALGORITHM["aes"];

	static BITS = {
		128: 128,
		192: 192,
		256: 256
	};
	static BITS_DEFAULT = this.BITS[256];

	static MODE = {
		cbc: "cbc",
		gcm: "gcm"
	};
	static MODE_DEFAULT = this.MODE["gcm"];

	static IV_LEN = {
		aes_cbc: 128,
		aes_gcm: 96
	};
	static GCM_TAG_LEN = 16; //Bytes (GCM hash tag)

	static HASH_ALGORITHM = {
		sha256: "sha256",
		scrypt: "scrypt"
	};
	static HASH_ALGORITHM_DEFAULT = this.HASH_ALGORITHM["scrypt"];
	static HASH_LEN_DEFAULT = this.BITS[256];

	static TYPE = {
		text: "text",
		hex: "hex",
		base64: "base64",
		buffer: "buffer",
		binary: "buffer"
	};

	//cryptographically secure random number generation
	static random() {
		return crypto.randomBytes(4).readUInt32LE() / 0xffffffff;
	}

	static encrypt({
		iv,
		key,
		plaintext,
		algorithm = this.SYMMETRIC_ALGORITHM_DEFAULT,
		bits = this.BITS_DEFAULT,
		mode = this.MODE_DEFAULT,
		output = this.TYPE["base64"],
		input = undefined,
		encoding = this.DEFAULT_ENCODING,
		showWarnings = false
	}) {
		//Cipher
		const cipher = this._assembleCipher(algorithm, bits, mode);
		//IV
		iv = this._parseToBuffer(iv, input, showWarnings);
		if (!this._checkIvLen(iv, cipher)) {
			throw new Error(this.STRINGS.error_invalidIvLen);
		}
		//Key
		key = this._parseToBuffer(key, input, showWarnings);
		if (key.byteLength * 8 !== bits) {
			throw new Error(this.STRINGS.error_invalidKeyLen);
		}
		//Plaintext
		plaintext = this._parseToBuffer(plaintext, input, showWarnings);
		//Output
		if (!(output in this.TYPE)) {
			throw new Error(this.STRINGS.error_invalidOutput);
		}

		//Encrypt
		const encipher = crypto.createCipheriv(cipher, key, iv);
		const ciphertext = Buffer.concat([encipher.update(plaintext, encoding), encipher.final()]);
		const tag = encipher.getAuthTag();
		const encrypted = Buffer.concat([ciphertext, tag]);
		//Output
		return this.convertOutput(encrypted, output);
	}

	static decrypt({
		iv,
		key,
		ciphertext,
		algorithm = this.SYMMETRIC_ALGORITHM_DEFAULT,
		bits = this.BITS_DEFAULT,
		mode = this.MODE_DEFAULT,
		output = this.TYPE["text"],
		input = undefined,
		encoding = this.DEFAULT_ENCODING,
		showWarnings = false
	}) {
		//Cipher
		const cipher = this._assembleCipher(algorithm, bits, mode);
		//IV
		iv = this._parseToBuffer(iv, input, showWarnings);
		if (!this._checkIvLen(iv, cipher)) {
			throw new Error(this.STRINGS.error_invalidIvLen);
		}
		//Key
		key = this._parseToBuffer(key, input, showWarnings);
		if (key.byteLength * 8 !== bits) {
			throw new Error(this.STRINGS.error_invalidKeyLen);
		}
		//Ciphertext
		ciphertext = this._parseToBuffer(ciphertext, input, showWarnings);
		//Output
		if (!(output in this.TYPE)) {
			throw new Error(this.STRINGS.error_invalidOutput);
		}

		//Decrypt
		const decipher = crypto.createDecipheriv(cipher, key, iv);
		decipher.setAuthTag(ciphertext.slice(-this.GCM_TAG_LEN));
		const decrypted = decipher.update(ciphertext.slice(0, ciphertext.byteLength - this.GCM_TAG_LEN), "binary") + decipher.final(encoding);
		//Output
		return this.convertOutput(decrypted, output);
	}

	static hash({
		value,
		salt,
		algorithm = this.HASH_ALGORITHM_DEFAULT,
		length = this.HASH_LEN_DEFAULT,
		options = undefined,
		output = this.TYPE["hex"],
		input = undefined,
		encoding = this.DEFAULT_ENCODING,
		showWarnings = false
	}) {
		//Value
		value = this._parseToBuffer(value, input, showWarnings);
		//Salt
		salt = salt || null;
		if (salt) {
			salt = this._parseToBuffer(salt, input, showWarnings);
		}
		//Output
		if (!(output in this.TYPE)) {
			throw new Error(this.STRINGS.error_invalidOutput);
		}

		//Hash
		let hashed = null;
		switch (algorithm) {
			case this.HASH_ALGORITHM["scrypt"]:
				//TODO: Add option for async
				hashed = crypto.scryptSync(value, salt, length / 8, options);
				break;
			case this.HASH_ALGORITHM["sha256"]:
			default:
				hashed = crypto
					.createHash(algorithm)
					.update(salt ? Buffer.concat([value, salt]) : value)
					.digest(encoding).buffer;
				break;
		}
		//Output
		return this.convertOutput(hashed, output);
	}

	static randomIV(ivLen) {
		return crypto.randomBytes(ivLen);
	}
	//GCM MUST NOT REUSE IV WITH SAME KEY
	//Although GCM key length can be variable, 12-bit is recommended
	//NIST SP-800-38D: 8.2.1 Deterministic Construction
	//
	//startIV = random byte array of length 12
	//Fixed numerical value stays same per message
	//Incremental numerical value that changes per message (sequence number)
	static deterministicIV({startIV, fixed, incremental, output = this.TYPE["hex"], input = undefined, encoding = this.DEFAULT_ENCODING, showWarnings = false}) {
		//startIV
		startIV = this._parseToBuffer(startIV, input, showWarnings);

		const nums = [];
		for (let i = 0; i < startIV.byteLength; i += 4) {
			let num = 0;
			num |= startIV[i] << 0;
			num |= startIV[i + 1] << 8;
			num |= startIV[i + 2] << 16;
			num |= startIV[i + 3] << 24;
			nums.push(num);
		}
		//GCM recommends first byte be fixed and last two dynamic per message
		nums[0] ^= fixed;
		nums[1] ^= incremental;
		nums[2] ^= incremental;
		const iv = Buffer.from(new Uint32Array(nums).buffer, encoding);
		//Output
		return this.convertOutput(iv, output);
	}

	//Hash the input and turn the first 4 bytes into a 32-bit number
	//This doesn"t need to be super unique as this value will get XOR"d with randomBytes
	//The output of this should be passed into deterministicIV "fixed" param
	static deterministic32BitVal({value, salt}) {
		const hash = this.hash({value, salt, length: 32, output: this.TYPE["buffer"]});
		let fixedVal = 0;
		fixedVal |= hash[0] << 0;
		fixedVal |= hash[1] << 8;
		fixedVal |= hash[2] << 16;
		fixedVal |= hash[3] << 24;
		return fixedVal;
	}

	static bufferToHex(arrayBuffer) {
		return Buffer.from(arrayBuffer).toString("hex");
	}
	static hexToBuffer(hex) {
		return Buffer.from(hex, "hex");
	}

	static base64ToBuffer(base64) {
		return Buffer.from(base64, "base64");
	}
	static bufferToBase64(buffer) {
		return buffer.toString("base64");
	}

	static atob(base64Encoded) {
		return Buffer.from(base64Encoded, "base64").toString();
	}
	static btoa(unencoded) {
		return Buffer.from(unencoded).toString("base64");
	}

	static generateRandomKey() {
		//TODO
	}

	static _assembleCipher(algorithm, bits, mode) {
		if (!(algorithm in this.SYMMETRIC_ALGORITHM)) {
			throw new Error(this.STRINGS.error_invalidAlgorithm);
		}
		if (!(bits in this.BITS)) {
			throw new Error(this.STRINGS.error_invalidBits);
		}
		if (!(mode in this.MODE)) {
			throw new Error(this.STRINGS.error_invalidMode);
		}
		return `${algorithm}-${bits}-${mode}`;
	}

	static _checkIvLen(iv, cipher) {
		const ivLen = this.IV_LEN[cipher.replace(/^([a-z]+)-([0-9]+)-([a-z]+)$/, "$1_$3")] || -1;
		return iv.byteLength * 8 === ivLen;
	}

	//Determine param type and convert to buffer
	static _parseToBuffer(param, knownType, showWarnings) {
		param = param || null;
		if (!param) {
			throw new Error(this.STRINGS.error_invalidParam);
		}
		knownType = knownType || null;
		showWarnings = showWarnings === true;

		//If we have a buffer return immediately
		if (Buffer.isBuffer(param)) {
			return param;
		}
		if (typeof param.buffer !== typeof undefined) {
			return Buffer.from(param.buffer);
		}

		if (!knownType) {
			if (typeof param === "string") {
				if (REGEX_HEX.test(param)) {
					knownType = this.TYPE["hex"];
					if (showWarnings) {
						console.warn(this.STRINGS.warning_assumedHex);
					}
				} else if (REGEX_BASE64.test(param)) {
					knownType = this.TYPE["base64"];
					if (showWarnings) {
						console.warn(this.STRINGS.warning_assumedBase64);
					}
				} else {
					knownType = this.TYPE["text"];
				}
			}
		}
		switch (knownType) {
			case this.TYPE["text"]:
				return Buffer.from(param, this.DEFAULT_ENCODING);
			case this.TYPE["hex"]:
				return this.hexToBuffer(param);
			case this.TYPE["base64"]:
				return this.base64ToBuffer(param);
		}

		throw new Error(this.STRINGS.error_unknownType);
	}

	static convertOutput(buffer, type) {
		//Output
		switch (type) {
			case this.TYPE["text"]:
				return buffer.toString();
			case this.TYPE["base64"]:
				return this.bufferToBase64(buffer);
			case this.TYPE["hex"]:
				return this.bufferToHex(buffer);
			case this.TYPE["buffer"]:
			case this.TYPE["binary"]:
				return buffer;
		}
		return null; //This line should never run... just here for good measure
	}

	static STRINGS = {
		warning_assumedHex: "Assumed type is hex",
		warning_assumedBase64: "Assumed type is base64",

		error_invalidAlgorithm: "Invalid algorithm",
		error_invalidBits: "Invalid bits",
		error_invalidMode: "Invalid mode",
		error_invalidIvLen: "Invalid iv length",
		error_invalidKeyLen: "Invalid key length",
		error_invalidOutput: "Invalid output",
		error_invalidParam: "Invalid param",
		error_unknownType: "Could not determine type"
	};
};
