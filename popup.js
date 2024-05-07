import { togglePassword, NotificationCenter, Store } from './store.js';

const password_container_elt = document.querySelector('#password-container');
const password_form_elt = document.querySelector('#password-form');
const master_password_elt = document.querySelector('#master-password');
const master_visibility_elt = document.querySelector('#master-visibility');
const entry_add_container_elt = document.querySelector('#entry-add-container');
const logout_elt = document.querySelector('#logout');
const store_action_elt = document.querySelector('#store-action');
const export_elt = document.querySelector('#export');
const import_action_elt = document.querySelector('#import-action');
const import_elt = document.querySelector('#import');
const entry_form_elt = document.querySelector('#entry-form');
const entry_name_elt = document.querySelector('#entry-name');
const entry_secret_elt = document.querySelector('#entry-secret');
const entry_visibility_elt = document.querySelector('#entry-visibility');
const entry_list_elt = document.querySelector('#entry-list');
const notification_elt = document.querySelector('#notification');
const notification_text_elt = document.querySelector('#notification-text');

let notification = new NotificationCenter(notification_elt, notification_text_elt);
let store = new Store(notification, entry_list_elt);
let background_port = browser.runtime.connect({name:"background"});

async function addEntry(event)
{
	event.preventDefault();
	// Remove any white spaces (can happen for readability)
	await store.addEntry(entry_name_elt.value, entry_secret_elt.value.replace(/\s/g, ''));
}

function start()
{
	password_container_elt.classList.add('hidden');
	[store_action_elt, import_action_elt, entry_add_container_elt].forEach(elt => {
		elt.classList.remove('hidden'); });
	store.refresh();
}

function stop()
{
	[store_action_elt, import_action_elt, entry_add_container_elt].forEach(elt => {
		elt.classList.add('hidden');
	});
	password_container_elt.classList.remove('hidden');
	store.close();
}

async function init()
{
	password_form_elt.addEventListener('submit', (event) => {
		event.preventDefault();
		background_port.postMessage({command: 'key', password: master_password_elt.value});
		master_password_elt.value = '';
	});
	master_visibility_elt.addEventListener('click', () => {togglePassword(master_password_elt);});
	entry_form_elt.addEventListener('submit', addEntry);
	entry_visibility_elt.addEventListener('click', () => {togglePassword(entry_secret_elt);});
	logout_elt.addEventListener('click', () => {
		background_port.postMessage({command: 'logout', password: master_password_elt.value});
		stop();
	});
	export_elt.addEventListener('click', () => { store.export(); });
	import_elt.addEventListener('click', () => { browser.tabs.create({ url: "options.html" }); });
	document.querySelector('#notification img').addEventListener(
		'click', notification.close_notification.bind(notification));

	background_port.postMessage({command: 'init'});
	background_port.onMessage.addListener((message) => {
		if(message.type === 'state')
		{
			if(message.data.key !== null)
				store.loadState(message.data).then(start);
		}
		else if(message.type === 'notification')
			notification.show_notification(message.data);
		else
			notification.show_error(`unexpected background message with type ${message.type}`);
	});
}

init().catch(error => {
	notification.show_error(error);
});
