// ---------------------------------------------------------------------
// Global JavaScript
// Authors: Andrew Ross & a little help from my friends
// ---------------------------------------------------------------------

/*jshint esversion: 6 */
var andrewrossco = andrewrossco || {};

(function($, APP) {

$(function() {
  APP.Global.init();
  APP.Viewport.init();
  APP.Modal.init();
  APP.ScrollTo.init();
});

// ---------------------------------------------------------------------
// Browser and Feature Detection
// ---------------------------------------------------------------------

APP.Global = {
  init: function() {

    $('body').addClass('page-ready');
    $('body').removeClass('no-js');

    if ( ! ('ontouchstart' in window) ) {
      document.documentElement.classList.add('no-touch');
    }

    if ( 'ontouchstart' in window ) {
      document.documentElement.classList.add('is-touch');
    }

    if (document.documentMode || /Edge/.test(navigator.userAgent)) {
      if(navigator.appVersion.indexOf('Trident') === -1) {
        document.documentElement.classList.add('isEDGE');
      } else {
        $('html').addClass('isIE isIE11');
      }
    }

    var isSafari = /constructor/i.test(window.HTMLElement) || (function (p) { return p.toString() === "[object SafariRemoteNotification]"; })(!window['safari'] || (typeof safari !== 'undefined' && safari.pushNotification));

    if(isSafari){
      document.body.classList.add('browser-safari');
    }

    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      document.body.classList.add('darkmode');
      document.getElementById('favicon').setAttribute('href', '/assets/img/favicons/favicon-light.png');
    }

    if(window.location.hostname == 'localhost' | window.location.hostname == '127.0.0.1'){
      document.body.classList.add('localhost');
    }

    $('.js-menu-trigger').click(function(e){
      e.preventDefault();
      if( $('body').hasClass('mobile-nav-open') ) {
        $('body').removeClass('mobile-nav-open');
      } else {
        $('body').addClass('mobile-nav-open');
      }
    });

    $(window).keyup(function (e) {
      var code = (e.keyCode ? e.keyCode : e.which);
      if (code == 9){
        if ($(window).width() < 768) {
          if ( $('.UnderlineNav-item:focus').length) {
            $('body').addClass('mobile-nav-open');
          } else {
            $('body').removeClass('mobile-nav-open');
          }
        }
      }
    });


    function timeSince(date) {
      var seconds = Math.floor((new Date() - date) / 1000);
      var interval = seconds / 31536000;
      if (interval > 1) {
        return Math.floor(interval) + " years";
      }
      interval = seconds / 2592000;
      if (interval > 1) {
        return Math.floor(interval) + " months";
      }
      interval = seconds / 86400;
      if (interval > 1) {
        return Math.floor(interval) + " days";
      }
      interval = seconds / 3600;
      if (interval > 1) {
        return Math.floor(interval) + " hours";
      }
      interval = seconds / 60;
      if (interval > 1) {
        return Math.floor(interval) + " minutes";
      }
      return Math.floor(seconds) + " seconds";
    }


    const dateAgo = $('.js-date-ago');
    dateAgo.each(function(){
      let el = $(this);
      let elHtml = el.html();
      let date = new Date(elHtml);
      let timeAgo = timeSince(date)
      el.html(timeAgo);
    });

    const dateAgoFormat = $('.js-date-ago-format');
    dateAgoFormat.each(function(){
      let el = $(this);
      let date = new Date(el.html());
      let timeAgo = timeSince(date)
      el.html(timeAgo);
    });
  }
};


// ---------------------------------------------------------------------
// Detect when an element is in the viewport
// ---------------------------------------------------------------------

APP.Viewport = {

  init: function() {
    let items = document.querySelectorAll('*[data-animate-in], *[data-detect-viewport]'),
    pageOffset = window.pageYOffset;

    function isScrolledIntoView(el) {
      var rect = el.getBoundingClientRect(),
      elemTop = rect.top,
      elemBottom = rect.top + el.offsetHeight,
      bottomWin = pageOffset + window.innerHeight;
      return (elemTop < bottomWin && elemBottom > 0);
    }

    function detect() {
      for(var i = 0; i < items.length; i++) {
        if ( isScrolledIntoView(items[i]) ) {
          if( !items[i].classList.contains('in-view') ) {
            items[i].classList.add('in-view');
          }
        }
      }
    }

    function throttle(fn, wait) {
      var time = Date.now();
      return function() {
        if ((time + wait - Date.now()) < 0) {
          fn();
          time = Date.now();
        }
      };
    }

    window.addEventListener('scroll', throttle(detect, 150));

    window.addEventListener('resize', detect);

    for(var i = 0; i < items.length; i++) {
      var d = 0,
      el = items[i];

      if( items[i].getAttribute('data-animate-in-delay') ) {
        d = items[i].getAttribute('data-animate-in-delay') / 1000 + 's';
      } else {
        d = 0;
      }
      el.style.transitionDelay = d;
    }

    $(document).ready(detect);
  }

};


// ---------------------------------------------------------------------
// Modal
// ---------------------------------------------------------------------

APP.Modal = {

  init: function() {

    // Click function
    const modalOpen = $('*[data-modal-target]');

    modalOpen.on('click touchstart:not(touchmove)', function(event) {
      event.preventDefault();
      let trigger = $(this).attr('data-modal-target');
      let target = $("#" + trigger);

      if( target.hasClass('is-active') ) {
        target.removeClass('is-active');
        $('body').removeClass('modal-is-active');
        target.find('.modal__content').removeClass('d-none');
        target.find('.share-modal-content').addClass('d-none');
      } else {
        target.addClass('is-active');
        $('body').addClass('modal-is-active');
      }
    });
  }
};


// ---------------------------------------------------------------------
// Scroll to
// ---------------------------------------------------------------------

APP.ScrollTo = {
  init: function() {
    if( $('*[data-scroll-to]').length ) {
      this.bind();
    } else {
      return;
    }
  },

  bind: function() {

    $('*[data-scroll-to]').on('click touchstart:not(touchmove)', function() {
      window.dispatchEvent(new Event('resize'));
      var trigger = $(this).attr('data-scroll-to'),
      target = $("#" + trigger),
      ss = 1000, //scroll speed
      o = 0; // offset

      if( $(this).attr('data-scroll-speed') ) {
        ss = $(this).attr('data-scroll-speed');
      }

      if( $(this).attr('data-scroll-offset') ) {
        o = $(this).attr('data-scroll-offset');
      }

      $('html, body').animate({
        scrollTop: target.offset().top - o
      }, ss);


    });


  }
};

}(jQuery, andrewrossco));
