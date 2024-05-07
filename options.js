import { NotificationCenter, Store } from './store.js';

const export_elt = document.querySelector('#export');
const import_elt = document.querySelector('#import');
const notification_elt = document.querySelector('#notification');
const notification_text_elt = document.querySelector('#notification-text');

let notification = new NotificationCenter(notification_elt, notification_text_elt);
let store = new Store(notification);
let background_port = browser.runtime.connect({name:"background"});

async function init()
{
	export_elt.addEventListener('click', () => {
		if(store.key === null)
			notification.show_error('Cannot export before login');
		else
			store.export();
	});
	import_elt.addEventListener('click', () => {
		if(store.key === null)
			notification.show_error('Cannot import before login');
		else
			store.import();
	});

	document.querySelector('#notification img').addEventListener(
		'click', notification.close_notification.bind(notification));

	background_port.postMessage({command: 'init'});
	background_port.onMessage.addListener((message) => {
		if(message.type === 'state')
		{
			if(message.data.key !== null)
				store.loadState(message.data);
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