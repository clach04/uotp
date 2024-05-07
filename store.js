const b32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function b32encode(bytes)
{
	let result = [];
	let index = 0;
	let lshift = 0;
	let carry = 0;
	let byte = bytes[index];
	while(index < bytes.length)
	{
		if(lshift < 0) // need to right shift (should have a carry)
		{
			result.push(b32chars[carry + (byte >>> (-lshift + 3))]);
			carry = 0;
			lshift += 5;
		}
		else if(lshift > 3) // not enough bits to convert (save carry, next will be right shift)
		{
			carry = ((byte << lshift) & 248) >> 3;
			lshift -= 8;
			index += 1;
			byte = bytes[index];
		}
		else // enough bits to convert
		{
			result.push(b32chars[((byte << lshift) & 248) >> 3]);
			lshift += 5;
		}
	}
	if(carry !== 0) // if carry left, add has last char
		result.push(b32chars[carry]);
	return result.join('');
}

function b32decode(text)
{
	const up_text = text.toUpperCase();
	let result = [];
	let lshift = 3;
	let carry = 0;
	for(const index in up_text)
	{
		const char = up_text[index];
		if(char === '=')
			break;
		let value = char.charCodeAt();
		if(value >= 65 && value <= 90) // char in [A- Z]
			value -= 65;
		else if(value >= 50 && value <= 55) // char in [2-7]
			value -= 24;
		else
			throw `Incorrect Base32 char '${text[index]}' at index ${index}`;

		if(lshift > 0) // next value is needed to complete the octet
		{
			carry += value << lshift;
			lshift -= 5;
			if(lshift === 0) // last value aligned with octet
				carry = 0;
		}
		else // getting the last octet' bits
		{
			result.push(carry + (value >>> (-lshift)));
			carry = (value << (lshift + 8)) & 248; // if lshit is 0 this will always be 0
			lshift += 3;
		}
	}
	if(carry !== 0)
		result.push(carry);
	return result;
}

export function togglePassword(elt)
{
	if(elt.getAttribute('type') === 'password')
		elt.setAttribute('type', 'text');
	else
		elt.setAttribute('type', 'password');
}

export class NotificationCenter
{
	constructor(notification_elt, notification_text_elt, notification_delay=5000, notification_repeat=500)
	{
		this.notifications = [];
		this.notification_timeout = null;
		this.notification_elt = notification_elt;
		this.notification_text_elt = notification_text_elt;
		this.notification_delay = notification_delay;
		this.notification_repeat = notification_repeat;
	}

	show_notification(text)
	{
		this.notifications.push(text);
		this._notification();
	}

	show_error(error)
	{
		console.error(error);
		this.show_notification(error);
	}

	close_notification()
	{
		clearTimeout(this.notification_timeout);
		this._next_notification();
	}

	_next_notification()
	{
		this.notification_timeout = null;
		this.notification_elt.classList.remove('show');
		this.notifications.shift();
		if(this.notifications.length !== 0)
			setTimeout(this._notification.bind(this), this.notification_repeat);
	}

	_notification()
	{
		if(this.notifications.length !== 0 && this.notification_timeout === null)
		{
			this.notification_text_elt.firstChild.data = this.notifications[0];
			this.notification_elt.classList.add('show');
			this.notification_timeout = setTimeout(this._next_notification.bind(this), this.notification_delay);
		}
	}
}

export class Store
{
	constructor(notification_center, entry_list_elt=null)
	{
		this.entries = [];
		this.iv = null;
		this.salt = null;
		this.key = null;

		this.refresh_timeout = null;

		this.entry_list_elt = entry_list_elt;
		this.notification_center = notification_center;
	}

	async loadState(state)
	{
		this.iv = state.iv;
		this.salt = state.salt;
		this.key = state.key;
		for(const entry of state.entries)
		{
			await this.addEntry(entry.name, entry.secret, false);
		}
		this.save();
	}

	async addEntry(name, secret, save=true)
	{
		const entry = await Entry.create(this, name, secret, this.notification_center);
		if(entry === null)
			return;
		if(this.entry_list_elt !== null)
			this.entry_list_elt.appendChild(entry.elements.main);
		this.entries.push(entry);
		if(save)
			this.save();
	}

	async removeEntry(entry)
	{
		if(this.entry_list_elt !== null)
			this.entry_list_elt.removeChild(entry.elements.main);
		this.entries = this.entries.filter(test_entry => test_entry !== entry);
		this.save();
	}

	async save()
	{
		if(this.key === null)
		{
			this.notification_center.show_error(`Cannot save store without key`);
			return;
		}
		let encoder = new TextEncoder();
		const encrypted = await window.crypto.subtle.encrypt(
			{name: 'AES-GCM', iv: this.iv},
			this.key,
			encoder.encode(JSON.stringify(
				this.entries.map(entry => {return {name: entry.name, secret: entry.secret};}))));
		await browser.storage.local.set({
			iv: b32encode(this.iv),
			salt: b32encode(this.salt),
			entries: b32encode(new Uint8Array(encrypted))
		});
	}

	refresh()
	{
		const now = Date.now();
		const count_time = now / 30000;
		const counter = Math.floor(count_time);
		const animation_delay = (count_time - counter) * 30;

		if(this.refresh_timeout !== null)
			clearTimeout(this.refresh_timeout);
		this.refresh_timeout = setTimeout(
			() => { this.refresh(); },
			((counter + 1) * 30000) - now + 1);

		for(const entry of this.entries)
		{
			entry.refresh(counter);
			entry.refreshTimer(animation_delay);
		}
	}

	close()
	{
		if(this.refresh_timeout !== null)
			clearTimeout(this.refresh_timeout);
		if(this.entry_list_elt !== null)
			this.entries.forEach(entry => { this.entry_list_elt.removeChild(entry.elements.main); });
		this.entries = [];
		this.key = null;
	}

	export()
	{
		const export_elt = document.createElement('a');
		export_elt.setAttribute('href', 'data:application/json,' + JSON.stringify(
			this.entries.map(entry => {return {name: entry.name, secret: entry.secret};})));
		export_elt.setAttribute('download', 'uotp_export.json');
		export_elt.style.display = 'none';
		document.body.appendChild(export_elt);
		export_elt.click();
		document.body.removeChild(export_elt);
	}

	import()
	{
		const import_elt = document.createElement('input');
		import_elt.setAttribute('type', 'file');
		import_elt.onchange = event => {
			if(event.target.files.length > 0)
			{
				let reader = new  FileReader();
				reader.onload = () => {
					let import_json = null;
					try
					{
						import_json = JSON.parse(reader.result);
					}
					catch(error)
					{
						this.notification_center.show_error('Error reading import file : not a valid json.');
					}
					if(!Array.isArray(import_json))
					{
						this.notification_center.show_error(
							'Invalid imported file : expecting a list of entries, imported JSON is not a list');
						return;
					}
					const errors = [];
					import_json.forEach((entry, index) => {
						if(!entry.name)
						{
							errors.push(`Invalid entry #${index} in imported file : "name" not found`);
							return;
						}
						if(!entry.secret)
						{
							errors.push(`Invalid entry #${index} in imported file : "secret" not found`);
							return;
						}
						this.addEntry(entry.name, entry.secret);
					});
					if(errors.length > 0)
						this.notification_center.show_error(
							`${errors.length} errors in imported file :\n${errors.join('\n')}`);
				};
				reader.readAsText(event.target.files[0]);
			}
		};
		document.body.appendChild(import_elt);
		import_elt.click();
		document.body.removeChild(import_elt);
	}
}

class Entry
{
	constructor(store, name, secret, key)
	{
		this.store = store;
		this.name = name;
		this.secret = secret;
		this.key = key;
		this.timer_count = 0;

		let new_elt = document.createElement('div');
		new_elt.className = 'entry';

		let header_elt = document.createElement('div');
		header_elt.className = 'header';
		// Entry title
		let title_elt = document.createElement('h2');
		title_elt.textContent = name;
		header_elt.appendChild(title_elt);

		// Entry actions
		let action_elt = document.createElement('div');
		action_elt.className = "action";
		let edit_elt = document.createElement('img');
		edit_elt.src = "/icons/edit.svg";
		edit_elt.title = 'Edit';
		edit_elt.addEventListener('click', () => {this.openEdit();});
		action_elt.appendChild(edit_elt);
		let delete_elt = document.createElement('img');
		delete_elt.src = "/icons/delete.svg";
		delete_elt.title = 'Delete';
		delete_elt.addEventListener('click', () => { this.store.removeEntry(this); });
		action_elt.appendChild(delete_elt);
		header_elt.appendChild(action_elt);

		new_elt.appendChild(header_elt);

		// Entry OTP
		let otp_container_elt = document.createElement('div');
		otp_container_elt.className = 'otp-container';
		let otp_elt = document.createElement('div');
		otp_elt.className = 'otp';
		otp_elt.addEventListener('click', () => {
			navigator.clipboard.writeText(otp_elt.textContent);
		});
		otp_container_elt.appendChild(otp_elt);
		// let svg_timer_elt = document.createElement('svg')
		const svgNS = 'http://www.w3.org/2000/svg';
		let svg_timer_elt = document.createElementNS(svgNS, 'svg');
		svg_timer_elt.setAttributeNS(null, 'viewBox', '0 0 2 2');
		let timer_circle_elt = document.createElementNS(svgNS, 'circle');
		timer_circle_elt.setAttributeNS(null, 'r', '1');
		timer_circle_elt.setAttributeNS(null, 'cx', '1');
		timer_circle_elt.setAttributeNS(null, 'cy', '1');
		svg_timer_elt.appendChild(timer_circle_elt);
		otp_container_elt.appendChild(svg_timer_elt);
		new_elt.appendChild(otp_container_elt);

		this.elements = {
			main: new_elt,
			header: header_elt,
			title: title_elt,
			otp: otp_elt,
			svg_timer_elt: svg_timer_elt,
			timer_circle: timer_circle_elt,
			action: action_elt,
			edit: edit_elt,
			delete: delete_elt
		};
	}

	// static function to construct Entry while being async
	static async create(store, name, secret, notification_center)
	{
		let decoded_secret = '';
		try
		{
			decoded_secret = new Uint8Array(b32decode(secret));
		}
		catch(error)
		{
			notification_center.show_error(error);
			return null;
		}
		const key = await window.crypto.subtle.importKey(
			'raw', decoded_secret, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
		const new_entry = new Entry(store, name, secret, key);
		const count_time = Date.now() / 30000;
		const counter = Math.floor(count_time);
		await new_entry.refresh(counter);
		new_entry.refreshTimer((count_time - counter) * 30);
		return new_entry;
	}

	async regenerateKey()
	{
		let decoded_secret = '';
		try
		{
			decoded_secret = new Uint8Array(b32decode(this.secret));
		}
		catch(error)
		{
			this.notification_center.show_error(error);
			return;
		}

		this.key = await window.crypto.subtle.importKey(
			'raw', decoded_secret, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
	}

	async refresh(counter)
	{
		// TOTP algorithm is here

		// Set timestamp as byte array for hmac hash (4 bytes is enough)
		const buffer = new ArrayBuffer(8); // 8 byte buffer needed for HMAC (initialized with 0)
		const view = new DataView(buffer);
		view.setUint32(4, counter);
		// HMAC returns am ArrayBuffer wich is unusable as is (no type), using Uint8Array is needed
		const signature = new Uint8Array(await window.crypto.subtle.sign("hmac", this.key, buffer));
		// Getting the offset from the last byte with its highest bit masked to 0
		const offset = signature[signature.length - 1] & 15;
		// Masking the highest bit of the byte located at calculated offset
		signature[offset] = signature[offset] & 127;
		// Reading 4 bytes from the hash from the offset (highest byte was masked) and getting the last
		// 6 digits from its Uint32 representation
		this.elements.otp.textContent = new DataView(
			signature.slice(offset, offset + 4).buffer).getUint32().toString().slice(-6);
	}

	refreshTimer(animation_delay)
	{
		this.timer_count = 1- this.timer_count;
		this.elements.timer_circle.style.animationDelay = `-${animation_delay}s`;
		this.elements.timer_circle.style.animationName = `timer${this.timer_count}`;
	}

	openEdit()
	{
		[this.elements.title, this.elements.otp, this.elements.edit, this.elements.delete,
			this.elements.svg_timer_elt].forEach(elt => {elt.classList.add('hidden');} );

		let name_input_elt = document.createElement('input');
		name_input_elt.value = this.name;
		this.elements.header.insertBefore(name_input_elt, this.elements.action);

		let secret_container_elt = document.createElement('div');
		secret_container_elt.className = 'password-container';
		let secret_input_elt = document.createElement('input');
		secret_input_elt.setAttribute('type', 'password');
		secret_input_elt.value = this.secret;
		secret_container_elt.appendChild(secret_input_elt);
		let secret_visibility_elt = document.createElement('img');
		secret_visibility_elt.className = 'icon visibility';
		secret_visibility_elt.src = '/icons/visibility.svg';
		secret_container_elt.appendChild(secret_visibility_elt);
		secret_visibility_elt.addEventListener('click', () => {togglePassword(secret_input_elt);});
		this.elements.main.appendChild(secret_container_elt);

		let done_elt = document.createElement('img');
		done_elt.src = "/icons/done.svg";
		done_elt.title = 'Save';
		this.elements.action.appendChild(done_elt);
		let close_elt = document.createElement('img');
		close_elt.src = "/icons/close.svg";
		close_elt.title = 'Cancel';
		this.elements.action.appendChild(close_elt);

		done_elt.addEventListener('click', () => {
			this.name = name_input_elt.value;
			this.elements.title.textContent = this.name;
			// Remove any white spaces (can happen for readability)
			this.secret = secret_input_elt.value.replace(/\s/g, '');
			this.regenerateKey().then(() => {
				const count_time = Date.now() / 30000;
				const counter = Math.floor(count_time);
				this.refresh(counter);
				this.refreshTimer((count_time - counter) * 30);
			});
			this.save();
			this.elements.main.removeChild(secret_container_elt);
			this.elements.action.removeChild(done_elt);
			this.elements.action.removeChild(close_elt);
			this.elements.header.removeChild(name_input_elt);
			this.closeEdit();
		});
		close_elt.addEventListener('click', () => {
			this.elements.main.removeChild(secret_container_elt);
			this.elements.action.removeChild(done_elt);
			this.elements.action.removeChild(close_elt);
			this.elements.header.removeChild(name_input_elt);
			this.closeEdit();
		});
	}

	closeEdit()
	{
		[this.elements.title, this.elements.otp, this.elements.edit, this.elements.delete,
			this.elements.svg_timer_elt].forEach(elt => { elt.classList.remove('hidden'); } );
	}
}
