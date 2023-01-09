#!/usr/bin/env node

//This file contains unit tests for NodeJS
const expect = require("chai").expect;

const CryptoProvider = require("../src/NodeCryptoProvider.js");

const testPhrase = "The quick brown fox jumps over the lazy dog";
describe("--- CryptoProvider ---\n", function () {
	it("random", function () {
		const val = CryptoProvider.random();
		expect(val).gte(0).lte(1);
	});

	it("encrypt", function () {
		const startIV = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12]);
		const fixed = CryptoProvider.deterministic32BitVal({value: "fixedPhrase", salt: "mySalt"});
		const incremental = 73;
		const deterministicIV = CryptoProvider.deterministicIV({startIV, fixed, incremental, output: CryptoProvider.TYPE["buffer"]});
		const key = CryptoProvider.hash({value: "mySecretKey", salt: "mySalt", output: CryptoProvider.TYPE["buffer"]});

		const ciphertext = CryptoProvider.encrypt({iv: deterministicIV, key, plaintext: testPhrase});
		expect(ciphertext).equal("HyNEqcat7b09fSU7b0P5Nv+5GWrbCHhxB1hIKbGyRy/AuLrUX2nII+gGbx2ILr1X4BbGOZ2GCYf9Byo=");
	});

	it("decrypt", function () {
		const startIV = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12]);
		const fixed = CryptoProvider.deterministic32BitVal({value: "fixedPhrase", salt: "mySalt"});
		const incremental = 73;
		const deterministicIV = CryptoProvider.deterministicIV({startIV, fixed, incremental, output: CryptoProvider.TYPE["buffer"]});
		const key = CryptoProvider.hash({value: "mySecretKey", salt: "mySalt", output: CryptoProvider.TYPE["buffer"]});

		const plaintext = CryptoProvider.decrypt({iv: deterministicIV, key, ciphertext: "HyNEqcat7b09fSU7b0P5Nv+5GWrbCHhxB1hIKbGyRy/AuLrUX2nII+gGbx2ILr1X4BbGOZ2GCYf9Byo="});
		expect(plaintext).equal(testPhrase);
	});

	it("hash", function () {
		const hash = CryptoProvider.hash({value: testPhrase, salt: "mySalt"});
		expect(hash).equal("ef2da2d985b06400f455d8801a11e8fe1bfe2cc35d72fa996a4254f6b4b54c2c");
	});

	it("randomIV", function () {
		const ivLen = CryptoProvider.IV_LEN[`${CryptoProvider.SYMMETRIC_ALGORITHM_DEFAULT}_${CryptoProvider.MODE_DEFAULT}`];
		const randomIV = CryptoProvider.randomIV(ivLen);
		expect(randomIV.length).equal(ivLen);
	});

	it("deterministicIV", function () {
		const startIV = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12]);
		const fixed = CryptoProvider.deterministic32BitVal({value: "fixedPhrase", salt: "mySalt"});
		const incremental = 73;
		const deterministicIV = CryptoProvider.deterministicIV({startIV, fixed, incremental});
		expect(deterministicIV).equal("de0bc0524c06070840101112");
	});
	it("deterministic32BitVal", function () {
		const fixedIV = CryptoProvider.deterministic32BitVal({value: "fixedPhrase", salt: "mySalt"});
		expect(fixedIV).equal(1455622623);
	});

	it("bufferToHex", function () {
		const hex = CryptoProvider.bufferToHex(new Uint8Array([0x01, 0x02, 0x03, 0x04]));
		expect(hex).equal("01020304");
	});
	it("hexToBuffer", function () {
		const byteArray = CryptoProvider.hexToBuffer("01020304");
		expect(byteArray[0]).equal(0x01);
		expect(byteArray[1]).equal(0x02);
		expect(byteArray[2]).equal(0x03);
		expect(byteArray[3]).equal(0x04);
	});

	it("atob", function () {
		const base64Encoded = CryptoProvider.btoa(testPhrase);
		expect(base64Encoded).equal("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");
	});
	it("btoa", function () {
		const unencoded = CryptoProvider.atob("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw");
		expect(unencoded).equal(testPhrase);
	});
});
