const body_elt = document.getElementsByTagName('body')[0]
const password_container_elt = document.querySelector('#password-container')
const password_form_elt = document.querySelector('#password-form')
const master_password_elt = document.querySelector('#master-password')
const master_visibility_elt = document.querySelector('#master-visibility')
const entry_add_container_elt = document.querySelector('#entry-add-container')
const logout_elt = document.querySelector('#logout')
const entry_form_elt = document.querySelector('#entry-form')
const entry_name_elt = document.querySelector('#entry-name')
const entry_secret_elt = document.querySelector('#entry-secret')
const entry_visibility_elt = document.querySelector('#entry-visibility')
const entry_list_elt = document.querySelector('#entry-list')

const b32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function togglePassword(elt)
{
	if(elt.getAttribute('type') === 'password')
		elt.setAttribute('type', 'text')
	else
		elt.setAttribute('type', 'password')
}

function b32encode(bytes)
{
	let result = []
	let index = 0
	let lshift = 0
	let carry = 0
	let byte = bytes[index]
	while(index < bytes.length)
	{
		if(lshift < 0) // need to right shift (should have a carry)
		{
			result.push(b32chars[carry + (byte >>> (-lshift + 3))])
			carry = 0
			lshift += 5
		}
		else if(lshift > 3) // not enough bits to convert (save carry, next will be right shift)
		{
			carry = ((byte << lshift) & 248) >> 3
			lshift -= 8
			index += 1
			byte = bytes[index]
		}
		else // enough bits to convert
		{
			result.push(b32chars[((byte << lshift) & 248) >> 3])
			lshift += 5
		}
	}
	if(carry !== 0) // if carry left, add has last char
		result.push(b32chars[carry])
	return result.join('')
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
		let value = char.charCodeAt() - 65
		if(value < 0)
			value += 41
		if(value < 0 || value > 31)
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

let refresh_timeout = null

class Store
{
	constructor()
	{
		this.entries = []
		this.iv = null
		this.salt = null
		this.key = null
	}

	async loadState(state)
	{
		this.iv = state.iv
		this.salt = state.salt
		this.key = state.key
		for(const entry of state.entries)
		{
			await store.addEntry(entry.name, entry.secret, false)
		}
		store.save()
	}

	async addEntry(name, secret, save=true)
	{
		const entry = await Entry.create(name, secret)
		entry.insert()
		this.entries.push(entry)
		if(save)
			this.save()
	}

	async removeEntry(entry)
	{
		entry.remove()
		this.entries = this.entries.filter(test_entry => test_entry !== entry)
		this.save()
	}

	async save()
	{
		if(this.key === null)
			throw `Cannot save store without key`
		let encoder = new TextEncoder();
		const entries = this.entries.map(entry => {return {name: entry.name, secret: entry.secret}})
		const encrypted = await window.crypto.subtle.encrypt(
			{name: 'AES-GCM', iv: this.iv},
			this.key,
			encoder.encode(JSON.stringify(entries)))
		await browser.storage.local.set({
			iv: b32encode(this.iv),
			salt: b32encode(this.salt),
			entries: b32encode(new Uint8Array(encrypted))
		})
	}

	refresh()
	{
		const now = Date.now()
		if(refresh_timeout !== null)
			clearTimeout(refresh_timeout)
		refresh_timeout = setTimeout(
			() => { store.refresh() },
			((Math.floor(now / 30000) + 1) * 30000) - now + 1)

		const counter = Math.floor(now / 30000)
		for(const entry of this.entries)
		{
			entry.refresh(counter)
		}
	}

	close()
	{
		this.entries.forEach(entry => { entry.remove() })
		this.entries = []
		this.key = null
	}
}

let store = new Store()

class Entry
{
	constructor(name, secret, key)
	{
		this.name = name
		this.secret = secret
		this.key = key

		let new_elt = document.createElement('div')
		new_elt.className = 'entry'

		let header_elt = document.createElement('div')
		header_elt.className = 'header'
		// Entry title
		let title_elt = document.createElement('h2')
		title_elt.textContent = name
		header_elt.appendChild(title_elt)

		// Entry actions
		let action_elt = document.createElement('div')
		action_elt.className = "action"
		let edit_elt = document.createElement('img')
		edit_elt.src = "/icons/edit.svg"
		edit_elt.addEventListener('click', () => {this.openEdit()})
		action_elt.appendChild(edit_elt)
		let delete_elt = document.createElement('img')
		delete_elt.src = "/icons/delete.svg"
		delete_elt.addEventListener('click', () => {store.removeEntry(this)})
		action_elt.appendChild(delete_elt)
		header_elt.appendChild(action_elt)

		new_elt.appendChild(header_elt)

		// Entry OTP
		let otp_elt = document.createElement('div')
		otp_elt.className = 'otp'
		otp_elt.addEventListener('click', () => {
			navigator.clipboard.writeText(this.signature)
		})
		new_elt.appendChild(otp_elt)

		this.elements = {
			main: new_elt,
			header: header_elt,
			title: title_elt,
			otp: otp_elt,
			action: action_elt,
			edit: edit_elt,
			delete: delete_elt
		}
	}

	// static function to construct Entry while being async
	static async create(name, secret)
	{
		const key = await window.crypto.subtle.importKey(
			'raw', new Uint8Array(b32decode(secret)), {name: 'HMAC', hash: 'SHA-1'}, false, ['sign'])
		const new_entry = new Entry(name, secret, key)
		await new_entry.refresh(Math.floor(Date.now() / 30000))
		return new_entry
	}

	async regenerateKey()
	{
		this.key = await window.crypto.subtle.importKey(
			'raw', new Uint8Array(b32decode(this.secret)), {name: 'HMAC', hash: 'SHA-1'}, false, ['sign'])
	}

	async refresh(counter)
	{
		// TOTP algorithm is here

		// Set timestamp as byte array for hmac hash (4 bytes is enough)
		const buffer = new ArrayBuffer(8); // 8 byte buffer needed for HMAC (initialized with 0)
		const view = new DataView(buffer);
		view.setUint32(4, counter)
		// HMAC returns am ArrayBuffer wich is unusable as is (no type), using Uint8Array is needed
		const signature = new Uint8Array(await window.crypto.subtle.sign("hmac", this.key, buffer))
		// Getting the offset from the last byte with its highest bit masked to 0
		const offset = signature[signature.length - 1] & 15
		// Masking the highest bit of the byte located at calculated offset
		signature[offset] = signature[offset] & 127
		// Reading 4 bytes from the hash from the offset (highest byte was masked) and getting the last
		// 6 digits from its Uint32 representation
		this.elements.otp.textContent = new DataView(
			signature.slice(offset, offset + 4).buffer).getUint32().toString().slice(-6)
	}

	insert()
	{
		entry_list_elt.appendChild(this.elements.main)
	}

	remove()
	{
		entry_list_elt.removeChild(this.elements.main)
	}

	openEdit()
	{
		this.elements.title.classList.add('hidden')
		this.elements.otp.classList.add('hidden')
		this.elements.edit.classList.add('hidden')
		this.elements.delete.classList.add('hidden')

		let name_input_elt = document.createElement('input')
		name_input_elt.value = this.name
		this.elements.header.insertBefore(name_input_elt, this.elements.action)

		let secret_container_elt = document.createElement('div')
		secret_container_elt.className = 'password-container'
		let secret_input_elt = document.createElement('input')
		secret_input_elt.setAttribute('type', 'password')
		secret_input_elt.value = this.secret
		secret_container_elt.appendChild(secret_input_elt)
		let secret_visibility_elt = document.createElement('img')
		secret_visibility_elt.className = 'icon visibility'
		secret_visibility_elt.src = '/icons/visibility.svg'
		secret_container_elt.appendChild(secret_visibility_elt)
		secret_visibility_elt.addEventListener('click', () => {togglePassword(secret_input_elt)})
		this.elements.main.appendChild(secret_container_elt)

		let done_elt = document.createElement('img')
		done_elt.src = "/icons/done.svg"
		this.elements.action.appendChild(done_elt)
		let close_elt = document.createElement('img')
		close_elt.src = "/icons/close.svg"
		this.elements.action.appendChild(close_elt)

		done_elt.addEventListener('click', () => {
			this.name = name_input_elt.value
			this.secret = secret_input_elt.value
			this.regenerateKey().then(() => { this.refresh(Math.floor(Date.now() / 30000)) })
			store.save()
			this.elements.main.removeChild(secret_container_elt)
			this.elements.action.removeChild(done_elt)
			this.elements.action.removeChild(close_elt)
			this.elements.header.removeChild(name_input_elt)
			this.closeEdit()
		})
		close_elt.addEventListener('click', () => {
			this.elements.main.removeChild(secret_container_elt)
			this.elements.action.removeChild(done_elt)
			this.elements.action.removeChild(close_elt)
			this.elements.header.removeChild(name_input_elt)
			this.closeEdit()
		})
	}

	closeEdit()
	{
		this.elements.title.classList.remove('hidden')
		this.elements.otp.classList.remove('hidden')
		this.elements.edit.classList.remove('hidden')
		this.elements.delete.classList.remove('hidden')
	}
}

async function addEntry(event)
{
	event.preventDefault()
	await store.addEntry(entry_name_elt.value, entry_secret_elt.value)
}

function start()
{
	password_container_elt.classList.add('hidden')
	entry_add_container_elt.classList.remove('hidden')
	const now = Date.now()
	if(refresh_timeout !== null)
			clearTimeout(refresh_timeout)
	refresh_timeout = setTimeout(
		() => {
			store.refresh()
		},
		((Math.floor(now / 30000) + 1) * 30000) - now + 1)
}

function stop()
{
	entry_add_container_elt.classList.add('hidden')
	password_container_elt.classList.remove('hidden')
	if(refresh_timeout !== null)
			clearTimeout(refresh_timeout)
	store.close()
}

let background_port = browser.runtime.connect({name:"background"});

async function init()
{
	password_form_elt.addEventListener('submit', (event) => {
		event.preventDefault()
		background_port.postMessage({command: 'key', password: master_password_elt.value})
		master_password_elt.value = ''
	})
	master_visibility_elt.addEventListener('click', () => {togglePassword(master_password_elt)})
	entry_form_elt.addEventListener('submit', addEntry)
	entry_visibility_elt.addEventListener('click', () => {togglePassword(entry_secret_elt)})
	logout_elt.addEventListener('click', () => {
		background_port.postMessage({command: 'logout', password: master_password_elt.value})
		stop()
	})

	background_port.postMessage({command: 'init'})
	background_port.onMessage.addListener((state) => {
		if(state.key !== null)
			store.loadState(state).then(() => start())
	})
}

init().catch(error => console.error(error))
