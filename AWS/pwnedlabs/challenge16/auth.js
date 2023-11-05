$(document).ready(function(){
    $(".btn-login").on("click", login);
});

function login(){
    email = $('#emailForm')[0].value;
    password = $('#passwordForm')[0].value;
    data = {'email':email, 'password':password};
    doLogin(data);
}
//Please remove this after testing. Password change is not necessary to implement so keep this secure!
function test_login(){
	data = {'email':'admin@huge-logistics.com', 'password':'H4mpturTiem213!'}
	doLogin(data);
}