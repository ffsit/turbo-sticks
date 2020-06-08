// requires scripts.js
// dom object wrapper
(function(name, baseObj) {
	"use strict";

	var rank_map = {
		bot: 7,
		crew: 6,
		mod: 5,
		helper: 4,
		vip: 3,
		turbo: 2,
		patron: 1,
		shadow: 0
	};

	var format_rank = {
		bot: 'Bots',
		crew: 'Crew',
		mod: 'Moderators',
		helper: 'Helpers',
		vip: 'Guests',
		turbo: 'TURBOs',
		patron: 'Patrons',
		shadow: 'Shadows'
	}

	// Private Members
	var _heartbeat = null;
	var _connected = false;
	var _connecting = false;
	var _resuming = false;
	var _channels = {};
	var _active_channel = null;
	var _show_join_leave_message = false;
	var _smooth_scroll = true;
	var _socket_uri = null;
	var _client_id = null;
	var _me = null;
	var _hyperlink_regex = /(\b(https?):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
	var _nick_color_seed = new Date().getUTCMonth();
	var _max_history_length = 200;
	var _send_timeout;
	var _connect_timeout;
	var _resume_timeout;

	// Methods
	function sorted_member_list(channel) {
		var members = [];
		var discord_members = channel.discord_members;
		var webchat_members = channel.webchat_members;
		for(var key in discord_members) {
			if(!webchat_members.hasOwnProperty(key)) {
				if(discord_members.hasOwnProperty(key)) {
					members[members.length] = discord_members[key];
				}
			}
		}
		for(var key in webchat_members) {
			if(webchat_members.hasOwnProperty(key)) {
				members[members.length] = webchat_members[key];
			}

		}
		members.sort(function(a, b) {
			var a_rank = rank_map[a['rank']];
			var b_rank = rank_map[b['rank']];
			if(a_rank > b_rank) {
				return -1;
			}
			if(a_rank < b_rank) {
				return 1;
			}
			var a_name = a['username'].toLowerCase();
			var b_name = b['username'].toLowerCase();
			if(a_name < b_name) {
				return -1;
			}
			if(a_name > b_name) {
				return 1;
			}
			return 0;
		});
		return members;
	}

	function find_member(channel, username) {
		var query = username || '';
		var discord_members = channel.discord_members;
		var webchat_members = channel.webchat_members;
		var member;
		query = query.toLowerCase(query);
		for(var key in webchat_members) {
			if(webchat_members.hasOwnProperty(key)) {
				member = webchat_members[key];
				if(member['username'].toLowerCase() === query) {
					return member;
				}
			}
		}
		for(var key in discord_members) {
			if(discord_members.hasOwnProperty(key)) {
				member = discord_members[key];
				if(member['username'].toLowerCase() === query) {
					return member;
				}
			}
		}
		return null; 
	}

	function get_member_key(member) {
		if(member['discord_id'] !== null) {
			return member['discord_id'];
		}
		return member['username'];
	}

	function format_username(member) {
		var username = member['username'];
		if(member['local'] === false) {
			var discriminator = member['discriminator'];
			username += '<span class="discriminator">#'+discriminator+'</span>';
		}
		return username;
	}

	function redraw_member_list() {
		if(_active_channel && _active_channel.name) {
			var channel = _active_channel;
			var wrapper = channel.tab.querySelector('.user-list-wrapper');
			if(wrapper && !sticks.hasClass(wrapper, 'hidden')) {
				var members = sorted_member_list(channel);
				var current_section = null;
				var html = '';
				var rank_name = '';
				for(var idx=0; idx < members.length; idx++) {
					var member = members[idx];
					var rank = member['rank'];
					var identity = get_member_key(member);
					var username = format_username(member);
					if(current_section !== rank) {
						current_section = rank;
						rank_name = format_rank[rank];
						if(idx > 0) {
							html += '</div></div>';
						}
						html += '<div class="'+current_section+'-section">';
						html += '<h3>'+rank_name+'</h3>';
						html += '<div class="'+current_section+'-section-body">';
					}
					html += '<div data-identity="'+identity+'" class="user-entry">';
					html += '<div class="role '+current_section+'">';
					html += '<div class="icon"></div>';
					html += '<div class="username">'+username+'</div></div></div>';
				}
				var user_list = wrapper.querySelector('.user-list');
				user_list.innerHTML = html;
			}
		}
	}

	function get_nick_color_class(name, seed) {
		var color = seed || _nick_color_seed;
		for(var idx = 0; idx < name.length; idx++) {
			color += name.charCodeAt(idx);
		}
		color = (color % 7) + 1;
		return 'nickColor' + color;
	}

	function toggle_login_window(show) {
		var login_wrapper = document.getElementById('login-wrapper');
		if(login_wrapper) {
			sticks.toggleClass(login_wrapper, 'hidden', !show);
		}
	}

	function toggle_spinner(show) {
		var spinner = document.querySelector('.spinner');
		var login_form = document.getElementById('loginform');
		if(spinner && login_form) {
			sticks.toggleClass(spinner, 'hidden', !show);
			sticks.toggleClass(login_form, 'hidden', show);
		}
	}

	function set_login_status(message, timeout) {
		var slide_message = document.getElementById('slide_message');
		slide_message.innerText = message || '';
		sticks.toggleClass(slide_message, 'hidden', !message);
		toggle_spinner(false);

		if(timeout) {
			setTimeout(function() {
				sticks.addClass(slide_message, 'hidden');
			}, timeout);
		}
	}

	function channel_window_hover(is_hovering) {
		if(_active_channel) {
			_active_channel.scroll_manager.pause(is_hovering);
		}
	}

	function user_list_toggle(element) {
		if(!sticks.hasClass(element, 'disabled')) {
			var wrapper = _active_channel.tab.querySelector('.user-list-wrapper');
			sticks.toggleClass(wrapper, 'hidden');
			redraw_member_list();
		}
	}

	function settings_menu_toggle(element) {
		if(!sticks.hasClass(element, 'disabled')) {
			var container = document.getElementById('settings-container');
			sticks.toggleClass(container, 'hidden');
		}
	}

	function handle_user_command(channel_name, command, args) {
		switch(command) {
			case '/quit':
			case '/q':
				sticks.chat.disconnect();
				return;

			case '/join':
				// TODO:
				return;

			case '/leave':
				// TODO:
				return;

			case '/broadcast':
			case '/!':
			case '%!':
				if(args.length < 1) {
					break;
				}
				sticks.chat.broadcast(args.join(' '));
				return;

			case '/ban':
				if(args.length < 1) {
					break;
				}
				sticks.chat.ban(args[0], args.slice(1).join(' '));
				return;

			case '/unban':
				if(args.length < 1) {
					break;
				}
				sticks.chat.unban(args[0], args.slice(1).join(' '));
				return;

			case '/timeout':
				if(args.length < 1) {
					break;
				}
				sticks.chat.timeout(args[0], args.slice(1).join(' '));
				return;

			case '/whisper':
			case '/tell':
			case '/r':
				if(args.length < 2) {
					break;
				}
				sticks.chat.whisper(args[0], args.slice(1).join(' '));
				return;

			case '/help':
			case '/h':
			case '/?':
				break;
		}
		sticks.chat.help(channel_name);
	}

	function on_message_timeout() {
		if(_active_channel) {
			write_error(_active_channel.name, 'Message Timeout',
				        'Server failed to respond in time.');
			enable_lower_ui(_active_channel.tab, true);
		}
	}

	function init_channel_tab_event_listeners(channel_tab, channel_name) {
		var channel_window = channel_tab.querySelector('.channel-window');
		sticks.on(channel_window, 'mouseenter mouseleave', function(e) {
			channel_window_hover(e.type === 'mouseenter');
			return sticks.preventDefault(e);
		});
		if(channel_name !== undefined) {
			var chatbox = channel_tab.querySelector('.chatbox');
			sticks.on(chatbox, 'keyup', function(e) {
				var content = e.currentTarget.value;
				if(e.which === 13 && content !== '') {
					e.currentTarget.value = '';
					e.currentTarget.setAttribute('disabled', 'disabled');
					_send_timeout = setTimeout(on_message_timeout, 5000);
					if(content[0] === '/' || content.slice(0, 2) === '%!') {
						var args = content.split(' ');
						handle_user_command(channel_name, args[0], args.slice(1));
					} else {
						sticks.chat.send_message(channel_name, content);
					}
				}
			});
		}
		var list_button = channel_tab.querySelector('.user-list-button');
		sticks.on(list_button, 'click', function(e) {
			user_list_toggle(e.currentTarget);
			return sticks.preventDefault(e);
		});
		var settings_button = channel_tab.querySelector('.user-settings-button');
		sticks.on(settings_button, 'click', function(e) {
			settings_menu_toggle(e.currentTarget);
			return sticks.preventDefault(e);
		});
	}

	function get_channel(channel_name) {
		var channel = _channels[channel_name];
		if(!channel) {
			var template = document.getElementById('channel-tab-template');
			var tab = template.cloneNode(true);
			var channel_window = tab.querySelector('.channel-window');
			var sm = sticks.ui.scrollManager(channel_window, _smooth_scroll);
			tab.id = 'channel-tab-' + channel_name;
			init_channel_tab_event_listeners(tab, channel_name);
			sticks.removeClass(tab, 'hidden');
			template.parentNode.appendChild(tab);
			channel = {
				name: channel_name,
				tab: tab,
				scroll_manager: sm,
				webchat_members: {},
				discord_members: {}
			}
			_channels[channel_name] = channel;
		}
		return channel;
	}

	function get_channel_window(channel) {
		return channel.tab.querySelector('.channel-window');
	}

	function pulse_channel_window(channel_name, activate) {
		var channel = get_channel(channel_name);
		var channel_window = get_channel_window(channel);
		sticks.toggleClass(channel_window, 'pulse', activate);
	}

	function toggle_channel_tab(channel_name) {
		for(var key in _channels) {
			if(_channels.hasOwnProperty(key)) {
				var channel = _channels[key];
				if(channel_name === channel.name) {
					_active_channel = channel;
					continue;
				}
				sticks.addClass(channel.tab, 'hidden');
				enable_lower_ui(channel.tab, false);
				channel.scroll_manager.stop();
			}
		}
		sticks.removeClass(_active_channel.tab, 'hidden');
		enable_lower_ui(_active_channel.tab, true);
		channel.scroll_manager.start();
	}

	function enable_chatbox(channel_tab, enable) {
		var chatbox = channel_tab.querySelector('.chatbox');
		if(chatbox) {
			if(enable) {
				chatbox.removeAttribute('disabled');
				chatbox.focus();
			} else {
				chatbox.setAttribute('disabled', 'disabled');
			}
		}
	}

	function enable_lower_ui(channel_tab, enable) {
		var buttons = channel_tab.querySelectorAll('.user-list-button');
		for(var idx = 0; idx < buttons.length; idx++) {
			sticks.toggleClass(buttons[idx], 'disabled',!enable);
		}
		enable_chatbox(channel_tab, enable);
	}

	function settings_item_toggle(element) {
		var button = element.querySelector('i');
		var toggled = !sticks.hasClass(button, 'fa-toggle-on');
		switch(element.getAttribute('data-settings-type')) {
			case 'turbo-mode':
				var channel_name = element.getAttribute('data-channels'); 
				set_turbo_mode(channel_name, toggled);
				break;

			case 'join-mode':
				_show_join_leave_message = toggled;
				sticks.set_cookie('join_mode', toggled ? 'show' : 'hide');
				break;

			case 'smooth-scroll-mode':
				_smooth_scroll = toggled;
				for(var key in _channels) {
					if(_channels.hasOwnProperty(key)) {
						_channels[key].scroll_manager.enable_smooth(toggled);
					}
				}
				sticks.set_cookie('smooth_scroll', toggled ? 'on' : 'off');
				break;

			case 'chat-theme':
				sticks.toggleClass(document.body, 'light-theme', toggled);
				sticks.set_cookie('chat_theme', toggled ? 'light' : 'dark');
				break;
		}
		sticks.toggleClass(button, 'fa-toggle-on');
		sticks.toggleClass(button, 'fa-toggle-off');
	}

	var _html_char_map = {
		'&': '&amp;',
		'<': '&lt;',
		'>': '&gt;',
		"'": '&apos;',
		'"': '&quot;',
	}
	function escape_html(message) {
		return message.replace(/[&<>'"]/g, function (chr) {
			return _html_char_map[chr];
		});
	}

	var _html_code_map = {
		'&amp;': '&',
		'&lt;': '<',
		'&gt;': '>',
		'&apos;': "'",
		'&quot;': '"',
	}
	function unescape_html(message) {
		return message.replace(/&[a-z]+;/g, function (code) {
			return _html_code_map[code];
		});
	}

	function parse_links(message) {
		if(_hyperlink_regex) {
			return message.replace(_hyperlink_regex, function(match) {
				var html = '<a href="'+unescape_html(match)+'" target="_blank">';
				html += escape_html(match);
				html += '</a>';
				return html;
			});
		}
		return message;
	}

	function write_info(channel_name, message, centered) {
		centered = centered === undefined ? true : centered;
		var channel = _channels[channel_name];
		var channel_window = get_channel_window(channel);
		var container = document.createElement('div');
		sticks.addClass(container, 'informative');
		if(centered) {
			sticks.addClass(container, 'text-center');
		}
		container.innerHTML = '<span class="message">'+message+'</span>';
		channel_window.appendChild(container);
	}

	function write_info_multiline(channel_name, lines) {
		for(var idx = 0; idx < lines.length; idx++) {
			write_info(channel_name, lines[idx], false);
		}
	}

	function write_error(channel_name, message, detail) {
		var channel = _channels[channel_name];
		var channel_window = get_channel_window(channel);
		var container = document.createElement('div');
		sticks.addClass(container, 'error');
		sticks.addClass(container, 'text-center');
		var html = '<span class="message">';
		html += '<b>Error: '+message+'</b>';
		if(detail) {
			html += '<br>' + detail;
		}
		html += '</span>';
		container.innerHTML = html;
		channel_window.appendChild(container);
	}

	function can_moderate() {
		var mod_ranking = rank_map['mod'];
		if(!mod_ranking) {
			return false;
		}

		var my_rank = _me['rank'] || 'shadow';
		var my_ranking = rank_map[my_rank];
		return my_ranking !== undefined && my_ranking >= mod_ranking;
	}

	function can_moderate_member(member) {
		var mod_ranking = rank_map['mod'];
		if(!mod_ranking) {
			return false;
		}

		var my_rank = _me['rank'] || 'shadow';
		var my_ranking = rank_map[my_rank];
		if(my_ranking === undefined || my_ranking < mod_ranking) {
			return false;
		}

		var rank = member['rank'] || 'shadow';
		var ranking = rank_map[rank];
		return ranking === undefined || my_ranking > ranking;
	}

	function is_me(member) {
		return get_member_key(member) === get_member_key(_me);
	}

	function write_message(channel_name, message, type) {
		var channel = _channels[channel_name];
		type = type || 'message';
		if(!channel || !_me) {
			return;
		}

		var css_classes = '';
		var member = message['author'];

		// normalize to local member if online
		var identity = get_member_key(member);
		if(member['local'] === false) {
			member = channel.webchat_members[identity] || member;
		}

		var prefix = '';
		if(type === 'whisper') {
			prefix = 'From ';
			var target = message['target'];
			var target_identity = get_member_key(target);
			if(target['local'] === false) {
				local_target = channel.webchat_members[target_identity];
				if(new_target !== undefined) {
					target = local_target;
				}
			}

			if(get_member_key(_me) === identity) {
				member = target;
				prefix = 'To ';
			}
		} else if(type === 'broadcast') {
			css_classes = 'modbroadcast';
		}

		var option_body = '';
		// member is at least a mod
		if(type === 'message' && can_moderate_member(member)) {
			option_body += '<span class="timeout">';
			option_body += '<i class="fa fa-ban" role="button" ';
			option_body += 'title="Timeout Chatter!"></i></span>';
		}

		var content = escape_html(message['content']);
		if(_me.rank !== 'crew') {
			content = parse_links(content);
		}

		var rank = member['rank'];
		var username = member['username'];
		username = (username[0] || '').toLocaleUpperCase() + username.substring(1);
		var nick_color_class = get_nick_color_class(username);
		username = prefix + username;

		var channel_window = channel.tab.querySelector('.channel-window');
		var container = document.createElement('div');
		sticks.addClass(container, 'user-entry');
		sticks.addClass(container, nick_color_class);
		container.setAttribute('data-identity', identity);
		container.setAttribute('data-message-id', message['id']);
		container.setAttribute('data-timestamp', message['created_at']);
		var html = '';
		html += '<div class="role '+rank+'">';
		html += '<div class="icon" title="'+format_rank[rank]+'"></div>';
		html += option_body;
		html += '<span class="username allowColor">'+username+':&nbsp;</span>';
		html += '<span class="message '+css_classes+'">'+content.trim()+'</span>';
		html += '</div>';
		container.innerHTML = html;
		if(option_body) {
			var timeout = container.querySelector('.timeout');
			if(timeout) {
				sticks.on(timeout, 'click', function() {
					sticks.chat.timeout(username);
				});
			}
		}
		channel_window.appendChild(container);
		trim_history(channel, channel_window);
	}

	function trim_history(channel, channel_window) {
		var messages = channel_window.querySelectorAll('.user-entry');
		var diff = _max_history_length - messages.length;
		for(var idx = diff; idx < 0; idx++) {
			var container = messages[idx-diff];
			var top = channel_window.scrollTop - container.clientHeight;
			channel_window.removeChild(container);
			channel_window.scrollTop = top;
			channel.scroll_manager.reset();
		}
	}

	function edit_message(channel_name, message) {
		var channel = _channels[channel_name];
		var message_id = message['id'];
		var content = message['content'];
		var channel_window = get_channel_window(channel);
		var selector = '.user-entry[data-message-id="'+message_id+'"]';
		var container = channel_window.querySelector(selector);
		if(container) {
			var element = container.querySelector('.message');
			if(element) {
				var orig_height = element.clientHeight;
				var top = channel_window.scrollTop;
				content = escape_html(content);
				if(_me.rank !== 'crew') {
					content = parse_links(content);
				}
				element.innerHTML = content;
				if(orig_height !== element.clientHeight) {
					channel_window.scrollTop = top - orig_height + element.clientHeight;
					channel.scroll_manager.reset();
				}
			}
		}
	}

	function delete_message(channel_name, message_id) {
		var channel = _channels[channel_name];
		var channel_window = get_channel_window(channel);
		var selector = '.user-entry[data-message-id="'+message_id+'"]';
		var container = channel_window.querySelector(selector);
		if(container) {
			var top = channel_window.scrollTop - container.clientHeight;
			channel_window.removeChild(container);
			channel_window.scrollTop = top;
			channel.scroll_manager.reset();
		}
	}

	function delete_member_messages(member) {
		var identity = get_member_key(member);
		var selector = '.channel-window .user-entry[data-identity="'+identity+'"]';
		var containers = document.querySelectorAll(selector);
		for(var idx = 0; idx < containers.length; idx++) {
			containers[idx].parentNode.removeChild(containers[idx]);
		}
		if(_active_channel) {
			_active_channel.scroll_manager.reset();
		}
	}

	function on_connection_timeout() {
		if(_connected === false && _connecting === true) {
			set_login_status('Connection timed out');
			close_socket();
		}
	}

	function on_resume_timeout() {
		if(_resuming === true) {
			set_login_status('Failed to resume chat session');
			close_socket();
			cleanup();
		}
	}

	// Main code to be executed on every page load
	function chat() {
		var loginform = document.getElementById('loginform');
		var channel_name = document.getElementById('channel_name');
		if(loginform && channel_name) {
			var selector;
			var button;
			if(sticks.get_cookie('chat_theme', 'dark') === 'light') {
				sticks.addClass(document.body, 'light-theme');
				selector = '.settings-item[data-settings-type=chat-theme] i';
				button = document.querySelector(selector);
				sticks.toggleClass(button, 'fa-toggle-on');
				sticks.toggleClass(button, 'fa-toggle-off');
			}
			if(sticks.get_cookie('smooth_scroll', 'on') === 'off') {
				_smooth_scroll = false;
				selector = '.settings-item[data-settings-type=smooth-scroll-mode] i';
				button = document.querySelector(selector);
				sticks.toggleClass(button, 'fa-toggle-on');
				sticks.toggleClass(button, 'fa-toggle-off');
			}
			if(sticks.get_cookie('join_mode', 'hide') === 'show') {
				_show_join_leave_message = true;
				selector = '.settings-item[data-settings-type=join-mode] i';
				button = document.querySelector(selector);
				sticks.toggleClass(button, 'fa-toggle-on');
				sticks.toggleClass(button, 'fa-toggle-off');
			}
			channel_name = channel_name.value;
			var webchat_uri = loginform.getAttribute('data-webchat-uri');
			sticks.on(loginform, 'submit', function(event) {
				sticks.preventDefault(event);
				sticks.chat.connect(webchat_uri, channel_name);
				toggle_spinner(true);
				pulse_channel_window(channel_name, true);
				_connect_timeout = setTimeout(on_connection_timeout, 5000);
				return false;
			});
			var tab = document.getElementById('channel-tab-template');
			init_channel_tab_event_listeners(tab);
			var settings_items = tab.parentNode.querySelectorAll('.settings-item');
			for(var idx=0; idx < settings_items.length; idx++) {
				sticks.on(settings_items[idx], 'click', function(e) {
					settings_item_toggle(e.currentTarget);
					return sticks.preventDefault(e);
				});
			}
		}
		sticks.on(window, 'beforeunload', disconnect)
	}

	function send_event(event, data) {
		if(chat.socket && chat.socket.readyState === WebSocket.OPEN) {
			var payload = {ev: event}
			if(data !== undefined) {
				payload['d'] = data;
			}
			chat.socket.send(JSON.stringify(payload));
		}
	}

	function send_heartbeat() {
		send_event('heartbeat');
	}

	function on_hello(data) {
		if(_client_id === null) {
			_client_id = data['client_id'];
		} else if(_client_id === data['client_id']) {
			// successful resume
			_resuming = false;
			clearTimeout(_resume_timeout);
		}
		_connected = true;
		_connecting = false;
		clearTimeout(_connect_timeout);
	}

	function on_message(channel_name, message) {
		write_message(channel_name, message, 'message');
	}

	function on_broadcast(message) {
		for(var key in _channels) {
			if(_channels.hasOwnProperty(key)) {
				write_message(_channels[key].name, message, 'broadcast');
			}
		}
	}

	function on_connection_success(channel_name, state) {
		_me = state['you'];
		var channel = get_channel(channel_name);
		channel.webchat_members = state['online_members']['webchat'];
		channel.discord_members = state['online_members']['discord'];

		var message_history = state['message_history'];
		for(var idx = 0; idx < message_history.length; idx++) {
			var message = message_history[idx];
			if(message['channel'] === 'broadcast') {
				on_broadcast(message);
			} else {
				on_message(channel_name, message);
			}
		}
		channel.scroll_manager.bottom();
		set_login_status();
		toggle_login_window(false);
		pulse_channel_window(channel_name, false);
		toggle_channel_tab(channel_name);
		write_info(channel_name, 'Connected to TURBO Sticks Webchat and joined '+
			                     'channel #'+channel_name);
	}

	function on_connect(channel_name, member) {
		var key = get_member_key(member);
		var channel = get_channel(channel_name);
		if(
			_show_join_leave_message === true &&
			channel.webchat_members[key] === undefined &&
			channel.discord_members[key] === undefined
		) {
			write_info(channel_name, member['username']+' joined #'+channel_name);
		}
		if(member['local'] === true) {
			channel.webchat_members[key] = member;
		} else if(member['local'] === false) {
			channel.discord_members[key] = member;
		}
		if(_active_channel && channel_name == _active_channel.name) {
			redraw_member_list();
		}
	}

	function on_disconnect(channel_name, member) {
		var key = get_member_key(member);
		var channel = get_channel(channel_name);
		if(member['local'] === true) {
			delete channel.webchat_members[key];
		} else if(member['local'] === false) {
			delete channel.discord_members[key];
		}
		if(channel_name == _active_channel.name) {
			redraw_member_list();
		}
		if(
			_show_join_leave_message === true &&
			channel.webchat_members[key] === undefined &&
			channel.discord_members[key] === undefined
		) {
			write_info(channel_name, member['username']+' left #'+channel_name);
		}
	}

	function on_whisper(message) {
		if(_active_channel) {
			write_message(_active_channel.name, message, 'whisper');
		}
	}

	function on_message_edit(channel_name, message) {
		edit_message(channel_name, message);
	}

	function on_message_delete(channel_name, message_id) {
		delete_message(channel_name, message_id);
	}

	function on_bulk_message_delete(channel_name, message_ids) {
		for(var idx = 0; idx < message_ids.length; idx++) {
			delete_message(channel_name, message_ids[idx]);
		}
	}

	function on_discord_connect(channel_name, state) {
		var channel = get_channel(channel_name);
		channel.discord_members = state['members'];
		if(_show_join_leave_message === true) {
			write_info(channel_name, 'Connection to Discord has been restored');
		}
		redraw_member_list();
	}

	function on_discord_disconnect() {
		var message = '';
		message += 'Lost connection to Discord. Messages will only be ';
		message += 'visible to Webchat users.';
		for(var key in _channels) {
			if(_channels.hasOwnProperty(key)) {
				_channels[key].discord_members = {};
				if(_show_join_leave_message === true) {
					write_info(key, message);
				}
			}
		}
		redraw_member_list();
	}

	function on_timeout_member(member, reason) {
		if(_active_channel) {
			if(is_me(member)) {
				write_info(_active_channel.name, 'You have been timed out.');
				if(reason) {
					write_info(_active_channel.name, 'Reason: '+reason);
				}
			}
			delete_member_messages(member);
		}
	}

	function on_ban_member(member, reason) {
		if(_active_channel) {
			if(is_me(member)) {
				write_info(_active_channel.name, 'You have been banned.');
				if(reason) {
					write_info(_active_channel.name, 'Reason: '+reason);
				}
			}
			delete_member_messages(member);
		}
	}

	function on_unban_member(member) {
		if(_active_channel) {
			if(is_me(member)) {
				write_info(_active_channel.name, 'Your ban/timeout has been lifted.');
			}
		}
	}


	function on_ack(info) {
		if(_active_channel) {
			enable_chatbox(_active_channel.tab, true);
			clearTimeout(_send_timeout);
			if(info) {
				write_info(_active_channel.name, info);
			}
		}
	}

	function on_error(message, detail) {
		console.error(message, detail);
		if(_active_channel) {
			write_error(_active_channel.name, message, detail);
			enable_chatbox(_active_channel.tab, true);
			clearTimeout(_send_timeout);
		}
	}

	function close_socket() {
		if(chat.socket) {
			if(chat.socket.readyState === WebSocket.OPEN) {
				chat.socket.close();
				chat.socket = null;
			} else if (chat.socket.readyState !== WebSocket.CONNECTING) {
				chat.socket = null;
			}
		}
	}

	function cleanup() {
			for(var key in _channels) {
				var tab = _channels[key].tab;
				tab.parentNode.removeChild(tab);
			}
			_active_channel = null;
			_channels = {};
			_client_id = null;
			_connected = false;
			_connecting = false;
			_resuming = false;
			toggle_login_window(true);
	}

	function open_socket(uri, onopen) {
		if(chat.socket) {
			return;
		}
		var socket = new WebSocket(uri);
		onopen = onopen || function() {
			send_event('connect', channel_name);
			_heartbeat = setInterval(send_heartbeat, 4000);
			console.log('Chat connected.');
		};
		socket.onopen = onopen;
		socket.onmessage = function(event) {
			var payload = JSON.parse(event.data);
			var event_name = payload['ev'];
			var data = payload['d'];
			console.log(payload);
			//TODO: grab this from event
			var channel_name = document.getElementById('channel_name');
			channel_name = channel_name.value;
			switch(event_name) {
				case 'hello':
					on_hello(data);
					break;

				case 'connection_success':
					on_connection_success(channel_name, data);
					break;

				case 'connect':
					on_connect(channel_name, data);
					break;

				case 'disconnect':
					on_disconnect(channel_name, data);
					break;

				case 'message':
					on_message(channel_name, data);
					break;

				case 'broadcast':
					on_broadcast(data);
					break;

				case 'whisper':
					on_whisper(data);
					break;

				case 'message_edit':
					on_message_edit(channel_name, data);
					break;

				case 'message_delete':
					on_message_delete(channel_name, data);
					break;

				case 'bulk_message_delete':
					on_bulk_message_delete(channel_name, data);
					break;

				case 'discord_connect':
					on_discord_connect(channel_name, data);
					break;

				case 'discord_disconnect':
					on_discord_disconnect();
					break;

				case 'timeout_member':
					on_timeout_member(data['member'], data['reason']);
					break;

				case 'ban_member':
					on_ban_member(data['member'], data['reason']);
					break;

				case 'unban_member':
					on_unban_member(data['member']);
					break;

				case 'ack':
					on_ack(data['info']);
					break;

				case 'error':
					on_error(data['message'], data['detail']);
					break;
			}
		};
		socket.onerror = function(event) {
			console.error(event);
		};
		socket.onclose = function(event) {
			if(_connected === true) {
				clearInterval(_heartbeat);
				console.log('Chat disconnected.');
				_connected = false;
				_connecting = false;
				resume();
			} else if(_connecting === true) {
				clearInterval(_heartbeat);
				cleanup();
				console.log('Chat disconnected.');
				set_login_status('Failed to reach server');
			}
		};
		chat.socket = socket;
	}

	function resume() {
		if(
			_resuming === false &&
			_connected === false &&
			_connecting === false &&
			_socket_uri !== null &&
			_client_id !== null
		) {
			_connecting = true;
			_resuming = true;
			open_socket(_socket_uri, function() {
				send_event('resume', {'client_id': _client_id});
				_heartbeat = setInterval(send_heartbeat, 4000);
				console.log('Attempting to resume chat session.');
			});
			_resume_timeout = setTimeout(on_resume_timeout, 5000);
			return;
		}
		cleanup();
		set_login_status('Lost connection to server.');
	}

	function connect(uri, channel_name) {
		if(_connected === false && _connecting === false) {
			_connecting = true;
			_socket_uri = uri;
			open_socket(uri);
		}
	}

	function disconnect() {
		if(_connected === true) {
			send_event('disconnect');
			cleanup();
			close_socket();
			clearTimeout(_send_timeout);
		}
	}

	function send_message(channel_name, content) {
		if(_connected === true && _active_channel) {
			send_event('message', {'channel_name': channel_name, 'content': content});
		}
	}

	function whisper(username, content) {
		if(_connected === true && _active_channel) {
			var member = find_member(_active_channel, username);
			if(member) {
				send_event('whisper', {'member': member, 'content': content});
			} else {
				write_error(_active_channel.name, 'Failed to whisper',
					        'No user with username "'+username+'" in current channel.');
				enable_chatbox(_active_channel.tab, true);
				clearTimeout(_send_timeout);
			}
		}
	}

	function broadcast(content) {
		if(_connected === true) {
			send_event('broadcast', {'content': content});
		}
	}

	function timeout(username, reason) {
		if(_connected === true) {
			var data = {};
			if(reason !== undefined) {
				data['reason'] = reason;
			}
			var member = find_member(_active_channel, username);
			if(member) {
				data['member'] = member;
				send_event('timeout_member', data);
			} else {
				write_error(_active_channel.name, 'Failed to timeout',
					        'No user with username "'+username+'" in current channel.');
				enable_chatbox(_active_channel.tab, true);
				clearTimeout(_send_timeout);
			}
		}
	}

	function ban(username, reason) {
		if(_connected === true) {
			var data = {};
			if(reason !== undefined) {
				data['reason'] = reason;
			}
			var member = find_member(_active_channel, username);
			if(member) {
				data['member'] = member;
				send_event('ban_member', data);
			} else {
				data['username'] = username;
				send_event('ban_username', data);
			}
		}
	}

	function unban(username) {
		if(_connected === true) {
			var member = find_member(_active_channel, username);
			if(member) {
				send_event('unban_member', {'member': member});
			} else {
				send_event('unban_username', {'username': username});
			}
		}
	}

	function help(channel_name) {
		if(_connected === true && _active_channel) {
			channel_name = channel_name || _active_channel.name;
			write_info_multiline(channel_name, [
                'The following commands are available:',
                'USAGE NOTE: Command [Alias] argument, (optional argument)',
                'EXAMPLE USAGE(1): /join #spoilers', 
                'EXAMPLE USAGE(2): /tell cafftest Hello.',
                '/help [/h /?] -- Help information this screen.',
                '/quit [/q] -- Quits the chat.',
                //'/join #channelName -- Joins a specific channel.',
                //'/leave -- Leaves the current channel.',
                '/whisper [/tell /r] nickname message -- Sends a private message to the nickname.'
			]);
			if(can_moderate()) {
				write_info_multiline(channel_name, [
					'Moderator commands:',
					'/broadcast [/! %!] message -- broadcast a message',
					'/timeout nickname reason -- Timeout user',
					'/ban nickname reason -- Ban user',
					'/unban nickname -- Unban user, also works on timeout'
				]);
			}

			enable_chatbox(_active_channel.tab, true);
			clearTimeout(_send_timeout);
		}
	}

	// Static Members
	chat.socket = null;
	chat.channel = null;
	chat.messages = [];
	chat.users = [];

	// Public Static Methods
	chat.connect = connect;
	chat.disconnect = disconnect;
	chat.send_message = send_message;
	chat.whisper = whisper;
	chat.broadcast = broadcast;
	chat.ban = ban;
	chat.unban = unban;
	chat.timeout = timeout;
	chat.help = help;
	chat.close_socket = close_socket;

	// Create public instance
	baseObj[name] = chat;
})('chat', sticks);

// run main code
sticks.chat();
