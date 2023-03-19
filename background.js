// state saved to restore data every time the popu is opened
let state = {
	iv: window.crypto.getRandomValues(new Uint8Array(12)),
	salt: window.crypto.getRandomValues(new Uint8Array(16)),
	key: null,
	entries: []
}

let popup_port = null // communication channel with popup

function send_state(state)
{
	popup_port.postMessage({type: 'state', data: state})
}

function show_error(error)
{
	console.error(error)
	popup_port.postMessage({type: 'notification', data: error})
}

function b32decode(text)
{
	const up_text = text.toUpperCase()
	let result = []
	let lshift = 3
	let carry = 0
	for(const index in up_text)
	{
		const char = up_text[index]
		if(char === '=')
			break
			let value = char.charCodeAt()
			if(value >= 65 && value <= 90) // char in [A- Z]
				value -= 65
			else if(value >= 50 && value <= 55) // char in [2-7]
				value -= 24
			else
				throw `Incorrect Base32 char '${text[index]}' at index ${index}`

		if(lshift > 0) // next value is needed to complete the octet
		{
			carry += value << lshift
			lshift -= 5
			if(lshift === 0) // last value aligned with octet
				carry = 0
		}
		else // getting the last octet' bits
		{
			result.push(carry + (value >>> (-lshift)))
			carry = (value << (lshift + 8)) & 248 // if lshit is 0 this will always be 0
			lshift += 3
		}
	}
	if(carry !== 0)
		result.push(carry)
	return result
}

// Create encryption key from password
async function setKey(password)
{
	const storage = await browser.storage.local.get()
	if(storage.entries !== undefined && storage.iv !== undefined && storage.salt !== undefined)
	{
		try
		{
			state.iv = new Uint8Array(b32decode(storage.iv))
			state.salt = new Uint8Array(b32decode(storage.salt))
		}
		catch(error)
		{
			show_error(error)
			return
		}
	}

	let encoder = new TextEncoder();
	const key_material = await window.crypto.subtle.importKey(
		'raw',
		encoder.encode(password),
		'PBKDF2',
		false,
		['deriveKey'])
	state.key = await window.crypto.subtle.deriveKey(
		{
			name: "PBKDF2",
			salt: state.salt,
			iterations: 20000,
			hash: "SHA-256",
		},
		key_material,
		{ "name": "AES-GCM", "length": 256},
		true,
		["encrypt", "decrypt"])
	// If entries are set in the state we automatically restore them
	if(storage.entries !== undefined)
		restore(storage)
	else
		send_state(state)
}

// Decrypt entries saved in local storage
async function restore(storage)
{
	let decoded_secret = null
	try
	{
		decoded_secret = new Uint8Array(b32decode(storage.entries))
	}
	catch(error)
	{
		show_error(error)
		return
	}

	try
	{
		let decrypted = await window.crypto.subtle.decrypt(
			{
				name: "AES-GCM",
				iv: state.iv
			},
			state.key, decoded_secret
		);

		let decoder = new TextDecoder();
		state.entries = JSON.parse(decoder.decode(decrypted))
		send_state(state)
	}
	catch(_error)
	{
		show_error('Cannot decrypt entries: wrong password')
	}
}

function connected(port) {
	popup_port = port
	popup_port.onMessage.addListener((message) => {
	  	if(message.command === 'init')
		{
			if(state.key === null)
				send_state(state)
			else
				browser.storage.local.get().then((storage) => { restore(storage) })
		}
		else if(message.command === 'key')
			setKey(message.password)
		else if(message.command === 'logout')
		{
			state.key = null
			state.entries = []
		}
		else
			show_error(`Wrong message: ${message}`)
	})
}

browser.runtime.onConnect.addListener(connected);