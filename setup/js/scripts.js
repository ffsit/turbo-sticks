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
	}

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

	function displayNotification(html, forever) {
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

		// Bubble click event to top window
		if(window.top != window.self) {
			document.querySelectorAll('body')[0].addEventListener('click', function() {
				var event = new MouseEvent('click', {
					view: window.top,
					bubbles: true,
					cancelable: true
				});
				window.top.document.querySelectorAll('body')[0].dispatchEvent(event);
			});
		}

		// App Password
		var reset_app_password = document.querySelectorAll('form[name=reset_app_password]')[0];
		if(reset_app_password) {
			// Copy App Password to Clipboard on Click
			var app_password = document.getElementById('app_password');
			app_password.addEventListener('click', function(event) {
				app_password.select();
				document.execCommand('copy');
				displayNotification('App-Password copied to clipboard.', false);
				return preventDefault(event);
			});

			// Reset App Password on Submit Click
			var csrf_token = reset_app_password.querySelectorAll('input[name=csrf_token]')[0].value;
			reset_app_password.addEventListener('submit', function(event) {
				ajax_post('/api/reset_app_password', 'csrf_token=' + csrf_token, function(data) {
					if(app_password && !data['error']) {
						app_password.value = data['app_password'];
					} else {
						displayNotification('<b>Error:</b> ' + data['error'], true);
					}
				}, function() {
					displayNotification('<b>Error:</b> Connection Error', true)
				});

				return preventDefault(event);
			});
		}

		// Maximize stream to headless
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
			var min = function () {
				removeClass(page, 'maximized');
				minimize.style.visibility = 'hidden';
			}
			minimize.addEventListener('click', min);
			document.onkeydown = function(event) {
				event = event || window.event;
				if(('key' in event && (event.key == 'Escape' || event.key == 'Esc')) ||
				   (event.keyCode == 27))
				{
					min();
				}
			};
			minimize.addEventListener('mouseenter', function() {
				minimize.style.opacity = 1;
			});
			minimize.addEventListener('mouseleave', function() {
				minimize.style.opacity = 0;
			});
			page.appendChild(minimize);
		}

		// Toggle Chat
		var chat_embed = document.getElementById('chat_embed');
		var player_embed = document.getElementById('player_embed');
		var toggle = document.getElementById('toggleview');
		if(chat_embed && player_embed && toggle)
		{
			// minimize / maximize chat
			var toggle_button = toggle.querySelectorAll('.button')[0];

			var minimize_chat = function() {
				toggle.removeEventListener('click', minimize_chat);
				toggle.addEventListener('click', maximize_chat);
				addClass(chat_embed, 'minimized');
				addClass(player_embed, 'maximized');
				removeClass(toggle_button, 'maximize');
				addClass(toggle_button, 'minimize');
			}

			var maximize_chat = function() {
				toggle.removeEventListener('click', maximize_chat);
				toggle.addEventListener('click', minimize_chat);
				removeClass(chat_embed, 'minimized');
				removeClass(player_embed, 'maximized');
				removeClass(toggle_button, 'minimize');
				addClass(toggle_button, 'maximize');
			}

			toggle.addEventListener('click', minimize_chat);
		}
	}

	function choose_video_source(index, player) {
		if(main.vsrc && player && index !== main.cur_video_source) {
			var video = main.vsrc[index];
			if(video) {
				player.innerHTML = '';

				switch(video.embed_type) {
					case 'html':
						player.innerHTML = video.embed;
						break;
				}

				main.cur_video_source = index;
			}
		}
	}

	function init_video(vsrc) {
		// stream source selection (legacy)
		var controls = document.getElementById('turboplayer_controls_wrapper');
		var select = document.getElementById('vsources');
		var player = document.getElementById('player');

		if(controls && select && player)
		{
			main.vsrc = vsrc;

			controls.addEventListener('mouseenter', function() {
				sticks.addClass(controls, 'turboplayer_controls_fadeIn');
			});

			controls.addEventListener('mouseleave', function() {
				sticks.removeClass(controls, 'turboplayer_controls_fadeIn');
				select.blur();
			});

			main.vsrc.map(function(video, index){
				// only add non-oven-player sources in legacy player
				if(video.embed_type.substr(0,5) !== 'oven-') {
					select[select.length] = new Option(video.label, index, false, select.length === 0);
				}
			});

			select.addEventListener('change', function() {
				choose_video_source(parseInt(select.value), player);
			});

			// init first video
			choose_video_source(0, player);
		}

		// stream source selection (oven-player)
		var ovenplayer = document.getElementById('ovenplayer');

		if(ovenplayer)
		{
			var oven_sources = vsrc.filter(function(video){
				return video.embed_type.substr(0,5) == 'oven-';
			}).map(function(video){
				return {
					type: video.embed_type.substr(5),
					file: video.embed,
					label: video.label
				};
			});
			main.ovenplayer = OvenPlayer.create('ovenplayer', {
				autoStart: true,
				image: '/static/movienight.png',
				sources: oven_sources
			});
		}
	}

	// Static Members
	main.notification = null;
	main.vsrc = null;
	main.cur_video_source = null;
	main.ovenplayer = null;

	// Public Static Methods
	main.ajax_post = ajax_post;
	main.init_video = init_video;
	main.addClass = addClass;
	main.removeClass = removeClass;
	main.displayNotification = displayNotification;
	main.hideNotifcation = hideNotifcation;
	main.preventDefault = preventDefault;

	// Create public instance
	baseObj[name] = main;
})('sticks', window);

// run main code
sticks();
