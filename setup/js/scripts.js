// dom object wrapper
(function(name, baseObj) {
	"use strict";

	// Methods
	function ajax_post(url, data, onsuccess, onerror) {
		var request = new XMLHttpRequest();
		request.open('POST', url, true);
		request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');

		if(onsuccess !== undefined && typeof onsuccess === 'function') {
			request.onload = function() {
				if(request.status >= 200 && request.status < 400) {
					// call onsucess with the parsed JSON object
					onsuccess(JSON.parse(request.responseText));
				} else {
					// call onsuccess with an object containing an error
					onsuccess({ error: 'Server returned status code ' + request.status });
				}
			};
		}

		if(onerror !== undefined && typeof onerror === 'function') {
			request.onerror = onerror;
		}

		request.send(data);
	};

	function addClass(element, className) {
		if(element.classList) {
			element.classList.add(className);
		} else {
			element.className += ' ' + className;
		}
	}

	function removeClass(element, className) {
		if(element.classList) {
			element.classList.remove(className);
		} else {
			element.className = element.className.replace(new RegExp('(^|\\b)' + className.split(' ').join('|') + '(\\b|$)', 'gi'), ' ');
		}
	}

	function preventDefault(event) {
		event.stopPropagation();
		event.preventDefault();
		return false;
	}

	function hideNotifcation() {
		removeClass(main.notification, 'shown');
	}

	function displayNotifcation(html, forever) {
		// Initialize notification
		if(!main.notification) {
			main.notification = document.getElementById('notification');
			if(!main.notifcation) {
				main.notification = document.createElement('div');
				main.notification.setAttribute('id', 'notification');
				document.querySelectorAll('body')[0].appendChild(main.notification);
				main.notification = document.getElementById('notification');
			}

			// Hide notification on click outside
			main.notification.addEventListener('click', preventDefault);
			document.querySelectorAll('body')[0].addEventListener('click', hideNotifcation);
		}

		// Display notification
		main.notification.innerHTML = html;
		addClass(main.notification, 'shown');

		if(!forever) {
			setTimeout(hideNotifcation, 1000);
		}
	}

	// Main code to be executed on every page load
	function main() {
		// Navigation Handling for Touch Devices
		var nav = document.getElementById('nav');
		if(nav !== null) {
			removeClass(nav, 'no-js');
			var upArrow = nav.querySelectorAll('li.arrow.up span')[0];
			var downArrow = nav.querySelectorAll('li.arrow.down span')[0];
			if(upArrow !== null && downArrow !== null) {
				downArrow.addEventListener('click', function() {
					addClass(nav, 'hover');
				});

				nav.addEventListener('mouseover', function() {
					addClass(nav, 'hover');
				});

				upArrow.addEventListener('click', function() {
					removeClass(nav, 'hover');
				});

				nav.addEventListener('mouseleave', function() {
					removeClass(nav, 'hover');
				});
			}
		}

		var reset_app_password = document.querySelectorAll('form[name=reset_app_password]')[0];
		if(reset_app_password) {
			// Copy App Password to Clipboard on Click
			var app_password = document.getElementById('app_password');
			app_password.addEventListener('click', function(event) {
				app_password.select();
				document.execCommand('copy');
				displayNotifcation('App-Password copied to clipboard.', false);
				return preventDefault(event);
			});

			// Reset App Password on Submit Click
			var csrf_token = reset_app_password.querySelectorAll('input[name=csrf_token]')[0].value;
			reset_app_password.addEventListener('submit', function(event) {
				ajax_post('/api/reset_app_password', 'csrf_token=' + csrf_token, function(data) {
					if(app_password && !data['error']) {
						app_password.value = data['app_password'];
					} else {
						displayNotifcation('<b>Error:</b> ' + data['error'], true);
					}
				}, function() {
					displayNotifcation('<b>Error:</b> Connection Error', true)
				});

				return preventDefault(event);
			});
		}
		var stream = document.getElementById('stream');
		if(stream) {
			var page = document.getElementById('page');
			var heading = page.querySelectorAll('h1')[0];
			var maximize = document.createElement('span');
			addClass(maximize, 'control');
			maximize.innerHTML = 'M';
			maximize.addEventListener('click', function(){
				addClass(page, 'maximized');
				minimize.style.visibility = 'visible';
			});
			heading.appendChild(maximize);

			var minimize = document.createElement('div');
			minimize.setAttribute('id', 'minimize');
			minimize.innerHTML = '<span class="control">m</span>';
			minimize.addEventListener('click', function(){
				removeClass(page, 'maximized');
				minimize.style.visibility = 'hidden';
			});
			minimize.addEventListener('mouseenter', function() {
				minimize.style.opacity = 1;
			});
			minimize.addEventListener('mouseleave', function() {
				minimize.style.opacity = 0;
			});
			page.appendChild(minimize);
		}
	};

	// Static Members
	main.notification = null;

	// Public Static Methods
	main.ajax_post = ajax_post;
	main.addClass = addClass;
	main.removeClass = removeClass;
	main.displayNotifcation = displayNotifcation;
	main.hideNotifcation = hideNotifcation;
	main.preventDefault = preventDefault;

	// Create public instance
	baseObj[name] = main;
})('sticks', window);

// run main code
sticks();
