$(function () {
    $(".post-comment").click(function () {
        var pid = $(".post-title").attr('id')
        var nickName = $("#nickname");
        var eMail = $("#email");
        var comment = $("#comment_content");
        var re = /[\w!#$%&'*+/=?^_`{|}~-]+(?:\.[\w!#$%&'*+/=?^_`{|}~-]+)*@(?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])?/
        var check_email = eMail.val().match(re);
        if (nickName.val() === "") {
            createAlert("请告诉我你的名字!")
            return
        }
        if (check_email === null) {
            createAlert("请检查邮箱是否正确哟~")
            return
        }
        if (comment.val() === "") {
            createAlert("评论不能空哟~")
            return
        }
        if (comment.val().length < 10) {
            createAlert("评论内容10个以上哟")
            return
        }
        var that = $(this)
        var floorNumMath = /\d+/
        var floorStr = $('.floor').text()
        var floorNum = floorStr.match(floorNumMath)
        $.ajax({
            url: '/comment',
            type: 'POST',
            data: {
                "paper": pid,
                "nickname": nickName.val(),
                "email": eMail.val(),
                "comment": comment.val(),
                "csrfmiddlewaretoken": $("input[name='csrfmiddlewaretoken']").attr("value")
            },
            success: function (data) {
                if (data.code == 200) {
                    comment.val("");
                    createAlert(data.msg);
                    var list = createFirstComment(data.data, Number(floorStr ? floorNum[0] : 0) + 1)
                    $(list).prependTo($('#j-comment-list'))    
		} else {
                    createAlert(data.msg)
                }
            }
        })
    })


    $("#j-comment-list").on('click', ".reply-btn", function () {
        $(this).parent().next().show()
        var idx = $(this).attr('id')
        var $reply_nickname = $("#reply-nickname-" + idx)
        var $reply_email = $("#reply-email-" + idx)
        $reply_nickname.val($("#nickname").val())
        $reply_email.val($("#email").val())
    })

    $("#j-comment-list").on('click', '.cancel-reply', function () {
        $(this).parent().parent().parent().hide()
    })


    $("#j-comment-list").on('click', '.post-reply', function () {
        var idx = $(this).attr('id')
        var pid = $(".post-title").attr('id')
        var $reply_nickname = $("#reply-nickname-" + idx)
        var $reply_email = $("#reply-email-" + idx)
        var $reply_comment = $("#reply-comment-" + idx)
        var re = /[\w!#$%&'*+/=?^_`{|}~-]+(?:\.[\w!#$%&'*+/=?^_`{|}~-]+)*@(?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])?/
        var check_email = $reply_email.val().match(re);
        if ($reply_nickname.val() === "") {
            createAlert("我该怎么称呼你?")
            return
        }
        if (check_email === null) {
            createAlert("请检查一下邮箱是否正确哦~")
            return
        }
        if ($reply_comment.val() === "") {
            createAlert("请大声说出你的想法~")
            return
        }
        if ($reply_comment.val().length < 10) {
            createAlert("回复内容为10个字以上哟")
            return
        }
        var that = $(this)
        $.ajax({
            url: '/comment',
            type: 'POST',
            data: {
                "paper": pid,
                "nickname": $reply_nickname.val(),
                "email": $reply_email.val(),
                "comment": $reply_comment.val(),
                "root": idx,
                "reply": idx,
                "depth": 2,
                "csrfmiddlewaretoken": $("input[name='csrfmiddlewaretoken']").attr("value")
            },
            success: function (data) {
                if (data.code == 200) {
                    $reply_comment.val("");
                    createAlert(data.msg)
                    // createAlert("管理员显示后就能看见啦！")
                    var html = createSecondComment(data.data)
                    console.log(data)
                    $(html).prependTo($('#j-comment-list li[id="' + idx + '"] .reply-list'))
                    that.parent().parent().parent().hide()
                } else {
                    createAlert(data.msg)
                }
            }

        })
    })

    $("#j-comment-list").on('click', '.reply-reply-btn', function () {
        $(this).parent().next().show()
        var idx = $(this).attr('id')
        var $reply_reply_nickname = $("#reply-reply-nickname-" + idx)
        var $reply_reply_email = $("#reply-reply-email-" + idx)
        $reply_reply_nickname.val($("#nickname").val())
        $reply_reply_email.val($("#email").val())
    })


    $("#j-comment-list").on('click', '.cancel-reply-reply', function () {
        $(this).parent().parent().parent().hide()
    })


    $("#j-comment-list").on('click', '.reply-reply', function () {
        var idx = $(this).attr('id')
        var root = $(this).attr('data-root-id')
        var pid = $(".post-title").attr('id')
        var $reply_reply_nickname = $("#reply-reply-nickname-" + idx)
        var $reply_reply_email = $("#reply-reply-email-" + idx)
        var $reply_reply_comment = $("#reply-reply-comment-" + idx)
        var that = $(this)
        var re = /[\w!#$%&'*+/=?^_`{|}~-]+(?:\.[\w!#$%&'*+/=?^_`{|}~-]+)*@(?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])?/
        var check_email = $reply_reply_email.val().match(re);
        if ($reply_reply_nickname.val() === "") {
            createAlert("我该怎么称呼你?")
            return
        }
        if (check_email === null) {
            createAlert("请检查一下邮箱是否正确哦~")
            return
        }
        if ($reply_reply_comment.val() === "") {
            createAlert("请大声说出你的想法~")
            return
        }
        if ($reply_reply_comment.val().length < 10) {
            createAlert("回复内容为10个字以上哟")
            return
        }
        $.ajax({
            url: '/comment',
            type: 'POST',
            data: {
                "paper": pid,
                "nickname": $reply_reply_nickname.val(),
                "email": $reply_reply_email.val(),
                "comment": $reply_reply_comment.val(),
                "reply": idx,
                "root": root,
                "depth": 3,
                "csrfmiddlewaretoken": $("input[name='csrfmiddlewaretoken']").attr("value")
            },

            success: function (data) {
                if (data.code == 200) {
                    $reply_reply_nickname.val("");
                    $reply_reply_email.val("");
                    $reply_reply_comment.val("");
                    createAlert(data.msg)
                    // createAlert("管理员显示后就能看见啦！")
                    var html = createThirdComment(data.data)
                    $(html).appendTo($('#j-comment-list li[id="' + root + '"] .reply-list li'))
                    that.parent().parent().parent().hide()
                } else {
                    createAlert(data.msg)
                }
            }

        })
    })

    $("#nickname").val(htmlEncode(Cookies.get('nickname')))
    $("#email").val(htmlEncode(Cookies.get('email')))

})

function createAlert(messages) {
    $(".error-box").append('<div class="message-holder animated  error" ' +
        'style="width: 800px; top: 40%;"><span class="content">' + messages +
        ' </span></div>').show().delay(1200).fadeOut();
    setTimeout(function () {
        $(".error-box").html("")
    }, 1500)
}

function htmlEncode(value) {
    return $('<div/>').text(value).html();
}

function createFirstComment(data, floor) {
    var html = '<li id="' + data.id + '">\n' +
        '                <div class="clearfix">\n' +
        '                    <div class="pull-left">\n' +
        '                        <img src="https://www.seebug.org/static/images/anonymous.jpg" class="avatar-b img-circle">\n' +
        '                    </div>\n' +
        '                    <div class="pull-left  comment-wrapper">\n' +
        '                        <div class="user-info">\n' +
        '                            <a class="user-name">[匿名用户]: ' + htmlEncode(data.nickname) + '</a>\n' +
        '                            <i class="sebug-icon icon-user-level-0"></i>\n' +
        '                            <time>' + data.date + '</time>\n' +
        '                        </div>\n' +
        '                        <div class="comment-content">\n' + htmlEncode(data.content) +
        '                        </div>\n' +
        '                        <!--回复列表 begin-->\n' +
        '                        <ul class="list-unstyled reply-list">\n' +
        '                        </ul>\n' +
        '                        <!--回复列表 end-->\n' +
        '                    </div>\n' +
        '                </div>\n' +
        '                <div class="operation text-right">\n' +
        '                    <a class="j-show-reply-form reply-btn" id="' + data.id + '">回复</a>\n' +
        '                </div>\n' +
        '                <form class="reply-form" action="" style="display: none">\n' +
        '                    <div>\n' +
        '                        <div class="col-md-6" style="margin-bottom: 20px">\n' +
        '                            <div class="input-group">\n' +
        '                                <span class="input-group-addon reply-nickname" id="basic-addon1">昵称</span>\n' +
        '                                <input type="text" class="form-control" placeholder="昵称(必填)" aria-describedby="basic-addon1" name="reply-nickname" id="reply-nickname-' + data.id + '">\n' +
        '                            </div>\n' +
        '                        </div>\n' +
        '                        <div class="col-md-6" style="margin-bottom: 20px">\n' +
        '                            <div class="input-group">\n' +
        '                                <span class="input-group-addon reply-email" id="basic-addon1">邮箱</span>\n' +
        '                                <input type="email" class="form-control" placeholder="邮箱(必填)" aria-describedby="basic-addon1" name="reply-email" id="reply-email-' + data.id + '">\n' +
        '                            </div>\n' +
        '                        </div>\n' +
        '                    </div>\n' +
        '                    <textarea name="" id="reply-comment-' + data.id + '" cols="30" rows="10" placeholder="请多说一点吧(10个字以上)" style="resize: none" class="reply-comment form-control"></textarea>\n' +
        '\n' +
        '\n' +
        '                    <div class="clearfix">\n' +
        '                        <div class="pull-right" style="margin-top: 10px;">\n' +
        '                            <button class="btn btn-brand-fill btn-submit-reply post-reply" type="button" id="' + data.id + '">回复\n' +
        '                            </button>\n' +
        '                            <button class="btn btn-brand-fill btn-cancel-reply cancel-reply" type="button" style="background-color: #aaa;">取消\n' +
        '                            </button>\n' +
        '                        </div>\n' +
        '                    </div>\n' +
        '                </form>\n' +
        '                <span class="floor">' + floor + 'F</span>\n' +
        '            </li>'

    return html
}

function createSecondComment(data) {
    var html = '<li>\n' +
        '\n' +
        '                                    <div class="reply-user-info">\n' +
        '                                                                <span class="reply-user-name">\n' +
        '                                                                    \n' + '[匿名用户]:' + htmlEncode(data.nickname) +
        '                                                                        ' +
        '                                                                    </span>\n' +
        '                                        <span class="reply_time">' + data.date + '</span>\n' +
        '                                    </div>\n' +
        '                                    <div class="reply-content">\n' +
        '                                        ' + htmlEncode(data.content) +
        '                                        <div class="operation text-right">\n' +
        '                                            <a class="j-show-reply-form reply-reply-btn" id="' + data.id + '">回复</a>\n' +
        '                                        </div>\n' +
        '                                        <form class="reply-form reply-reply-form" action="" style="display: none">\n' +
        '                                            <div>\n' +
        '                                                <div class="col-md-6" style="margin-bottom: 20px">\n' +
        '                                                    <div class="input-group">\n' +
        '                                                        <span class="input-group-addon reply-nickname" id="basic-addon1">昵称</span>\n' +
        '                                                        <input type="text" class="form-control" placeholder="昵称(必填)" aria-describedby="basic-addon1" name="reply-nickname" id="reply-reply-nickname-' + data.id + '">\n' +
        '                                                    </div>\n' +
        '                                                </div>\n' +
        '                                                <div class="col-md-6" style="margin-bottom: 20px">\n' +
        '                                                    <div class="input-group">\n' +
        '                                                        <span class="input-group-addon reply-email" id="basic-addon1">邮箱</span>\n' +
        '                                                        <input type="email" class="form-control" placeholder="邮箱(必填)" aria-describedby="basic-addon1" name="reply-email" id="reply-reply-email-' + data.id + '">\n' +
        '                                                    </div>\n' +
        '                                                </div>\n' +
        '                                            </div>\n' +
        '                                            <textarea name="" id="reply-reply-comment-' + data.id + '" cols="30" rows="10" placeholder="请多说一点吧(10个字以上)" style="resize: none" class="reply-reply-comment form-control"></textarea>\n' +
        '\n' +
        '\n' +
        '                                            <div class="clearfix">\n' +
        '                                                <div class="pull-right" style="margin-top: 10px;">\n' +
        '                                                    <button class="btn btn-brand-fill btn-submit-reply reply-reply" type="button" id="' + data.id + '" data-root-id="' + data.root + '">\n' +
        '                                                        回复\n' +
        '                                                    </button>\n' +
        '                                                    <button class="btn btn-brand-fill btn-cancel-reply cancel-reply-reply" type="button" style="background-color: #aaa;">取消\n' +
        '                                                    </button>\n' +
        '                                                </div>\n' +
        '                                            </div>\n' +
        '                                        </form>\n' +
        '                                    </div>\n' +
        '\n' +
        '                                    \n' +
        '                            </li>'
    return html
}

function createThirdComment(data) {
    var html = '<div class="reply-reply-list">\n' +
        '                                                <div class="reply-user-info">\n' +
        '                                                                <span class="reply-user-name">\n' +
        '                                                                    \n' +
        '                                                                        [匿名用户]:' + htmlEncode(data.nickname) +
        '                                                                    </span>\n' +
        '                                        <span class="reply_time">' + data.date + '</span>\n' +
        '                                    </div>\n' +
        '                                                <div class="reply-content">\n' +
        htmlEncode(data.content) +
        '                                    </div>\n' +
        '\n' +
        '                                            </div>'
    return html
}


