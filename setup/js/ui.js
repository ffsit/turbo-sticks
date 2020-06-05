// requires scripts.js
// dom object wrapper
(function(name, baseObj) {
	"use strict";

	// Private Members

	// Methods

	// Main code to be executed on every page load
	function ui() {
		return;
	}

	// Classes
	var scrollManager = function(element, smooth_scroll) {
		var self = {
			element: element,
			smooth_scroll: smooth_scroll,
			state: 'stopped',
			interval: null,
			top: null,
		};

		self.enable_smooth = function(smooth_scroll) {
			self.smooth_scroll = smooth_scroll;
		};

		self.scroll_loop = function() {
			if(self.state === 'stopped') {
				return;
			}
			self.interval = setTimeout(function() {
				if(self.state === 'started') {
					var height = self.element.scrollHeight;
					var top = self.top || self.element.scrollTop;
					var bottom = Math.ceil(top + self.element.clientHeight);
					if(bottom < height) {
						if(self.smooth_scroll) {
							var rate = 1;
							if(bottom < height - 140) {
								rate = 1 + Math.round((height - bottom)/50);
							}
							height = top + rate;
						}
						element.scrollTop = height;
						// we want to record where we scrolled to in case the DOM
						// is too slow to update. otherwise we might stop scrolling
						self.top = height;
					}
				}
				self.scroll_loop();
			}, 33);
		};

		// this needs to be called whenever we scroll backwards
		self.reset = function() {
			self.top = null;
		}

		self.bottom = function() {
			self.element.scrollTop = self.element.scrollHeight;
			self.reset();
		}

		self.start = function() {
			self.state = 'started';
			self.reset();
			// don't spawn multiple scroll loops
			if(self.interval === null) {
				self.scroll_loop();
			}
		};

		self.stop = function() {
			self.state = 'stopped';
			clearTimeout(self.interval);
			self.interval = null;
		};

		self.pause = function(activate) {
			if(self.state !== 'stopped') {
				self.state = activate ? 'paused' : 'started';
				self.reset();
			}
		};

		return self;
	};

	ui.scrollManager = scrollManager;

	// Create public instance
	baseObj[name] = ui;
})('ui', sticks);
