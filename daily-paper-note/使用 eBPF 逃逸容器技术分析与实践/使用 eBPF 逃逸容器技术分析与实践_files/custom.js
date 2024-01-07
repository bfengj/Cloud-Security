$(document).ready(function () {
    var $wrapper = $('#wrapper');
    var back_top = $("#backtop");
    console.log(back_top);
    back_top.hide();
    //获取页面的可视窗口高度
    var clientHeight = document.documentElement.clientHeight || document.body.clientHeight;
    var timer = null;
    var isTop = true;
    var osTop = null;
    window.onscroll = function () {
        osTop = document.documentElement.scrollTop || document.body.scrollTop;
        if (osTop >= clientHeight) {
            back_top.show();
        } else {
            back_top.hide();
        }

        if (!isTop) {
            clearInterval(timer);
        }
        isTop = false;
    };
    back_top.on('click', function () {
        timer = setInterval(function () {
            var osTop = document.documentElement.scrollTop || document.body.scrollTop;  //同时兼容了ie和Chrome浏览器
            var isSpeed = Math.floor(-osTop / 6);
            document.documentElement.scrollTop = document.body.scrollTop = osTop + isSpeed;
            isTop = true;
            if (osTop === 0) {
                clearInterval(timer);
            }
        }, 30);
    });

    $('[data-toggle="offcanvas"]').click(function () {
        $wrapper.toggleClass('toggled');
        if ($wrapper.hasClass('toggled')) {
            Cookies.set('sidebar-state', 'close');
        } else {
            Cookies.set('sidebar-state', 'open');
        }
    });
    $(function () {
        $('.collapse-link').on('click', function () {
            var $BOX_PANEL = $(this).closest('.x_panel'),
                $ICON = $(this).find('i'),
                $BOX_CONTENT = $BOX_PANEL.find('.toc');

            // fix for some div with hardcoded fix class
            if ($BOX_PANEL.attr('style')) {
                $BOX_CONTENT.slideToggle(200, function () {
                    $BOX_PANEL.removeAttr('style');
                });
            } else {
                $BOX_CONTENT.slideToggle(200);
                $BOX_PANEL.css('height', 'auto');
            }

            $ICON.toggleClass('fa-chevron-up fa-chevron-down');
        });

        $('.close-link').click(function () {
            var $BOX_PANEL = $(this).closest('.x_panel');

            $BOX_PANEL.remove();
        });
    });
});
