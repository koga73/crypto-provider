const crypto = window.crypto || window.msCrypto || null;

export class CryptoProvider {
	static SYMMETRIC_ALGORITHM = "AES-GCM";
	static IV_LEN = 12; //Bytes
	static KEY_LEN = 32; //Bytes (32 * 8 = 256-bit)
	static TAG_LEN = 16; //Bytes (GCM hash tag)
	static HASH_ALGORITHM = "SHA-256";

	static getCrypto() {
		return crypto;
	}

	static isSupported() {
		return crypto !== null;
	}

	//Cryptographically secure random number generation
	//https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
	static random() {
		return crypto.getRandomValues(new Uint32Array(1))[0] / 0xffffffff;
	}

	//Returns promise
	static loadKeySymmetric(arrayBuffer) {
		//Fourth parameter "false" means the key is not extractable
		return crypto.subtle.importKey("raw", arrayBuffer, this.SYMMETRIC_ALGORITHM, false, ["encrypt", "decrypt"]);
	}

	//Returns promise
	static encrypt(iv, key, plaintext) {
		if (iv.byteLength != this.IV_LEN) {
			throw new Error("invalid iv length");
		}
		if (key && key.algorithm && key.algorithm.length / 8 != this.KEY_LEN) {
			throw new Error("invalid key length");
		}
		if (typeof plaintext === "string") {
			plaintext = new TextEncoder().encode(plaintext);
		}
		return crypto.subtle.encrypt(
			{
				name: this.SYMMETRIC_ALGORITHM,
				iv: iv
			},
			key,
			plaintext
		);
	}

	//Returns promise
	static decrypt(iv, key, ciphertext) {
		if (iv.byteLength != this.IV_LEN) {
			throw new Error("invalid iv length");
		}
		if (key && key.algorithm && key.algorithm.length / 8 != this.KEY_LEN) {
			throw new Error("invalid key length");
		}
		if (typeof ciphertext === "string") {
			ciphertext = this.base64ToArrayBuffer(ciphertext);
		}
		return crypto.subtle.decrypt(
			{
				name: this.SYMMETRIC_ALGORITHM,
				iv: iv
			},
			key,
			ciphertext
		);
	}

	//Returns promise
	static hash(phrase, optionalRawSalt) {
		optionalRawSalt = optionalRawSalt || null;

		let toHash = new TextEncoder().encode(phrase);
		if (optionalRawSalt) {
			const tmp = new Uint8Array(optionalRawSalt.byteLength + toHash.byteLength);
			tmp.set(new Uint8Array(optionalRawSalt));
			tmp.set(toHash, optionalRawSalt.byteLength);
			toHash = tmp;
		}
		return crypto.subtle.digest(this.HASH_ALGORITHM, toHash).then(function (hash) {
			return Promise.resolve(new Uint8Array(hash));
		});
	}

	static randomIV() {
		return crypto.getRandomValues(new Uint8Array(this.IV_LEN));
	}

	//GCM MUST NOT REUSE IV WITH SAME KEY
	//Although GCM key length can be variable, 12-bit is recommended
	//NIST SP-800-38D: 8.2.1 Deterministic Construction
	//
	//startIV = random byte array of length 12
	//Fixed numerical value stays same per message
	//Incremental numerical value that changes per message (sequence number)
	static deterministicIV(startIV, fixed, incremental) {
		if (startIV.byteLength != this.IV_LEN) {
			throw new Error("invalid startIV length");
		}
		const nums = [];
		startIV = new Uint8Array(startIV);
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
		return new Uint8Array(new Uint32Array(nums).buffer);
	}

	//Hash the input and turn the first 4 bytes into a 32-bit number
	//This doesn"t need to be super unique as this value will get XOR"d with randomBytes
	//The output of this should be passed into deterministicIV "fixed" param
	static deterministic32BitVal(phrase) {
		return this.hash(phrase).then(function (hash) {
			let fixedVal = 0;
			fixedVal |= hash[0] << 0;
			fixedVal |= hash[1] << 8;
			fixedVal |= hash[2] << 16;
			fixedVal |= hash[3] << 24;
			return Promise.resolve(fixedVal);
		});
	}

	//Grabbed from: https://stackoverflow.com/a/40031979/3610169
	static arrayBufferToHex(arrayBuffer, delimiter) {
		delimiter = delimiter || "";
		return Array.prototype.map
			.call(new Uint8Array(arrayBuffer), function (x) {
				return ("00" + x.toString(16)).slice(-2);
			})
			.join(delimiter);
	}
	static hexToArrayBuffer(hex) {
		return new Uint8Array(
			hex.match(/[\da-f]{2}/gi).map(function (h) {
				return parseInt(h, 16);
			})
		).buffer;
	}

	//Grabbed from: https://stackoverflow.com/a/21797381/3610169
	static base64ToArrayBuffer(base64) {
		const binary_string = atob(base64);
		const len = binary_string.length;
		const bytes = new Uint8Array(len);
		for (let i = 0; i < len; i++) {
			bytes[i] = binary_string.charCodeAt(i);
		}
		return bytes.buffer;
	}
	static arrayBufferToBase64(arrayBuffer) {
		return btoa(
			new Uint8Array(arrayBuffer).reduce(function (data, byte) {
				return data + String.fromCharCode(byte);
			}, "")
		);
	}
}
