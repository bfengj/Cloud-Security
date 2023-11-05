$(document).ready(function(){
    $(".btn-login").on("click", login);
});

function login(){
    email = $('#emailForm')[0].value;
    password = $('#passwordForm')[0].value;
    data = {'email':email, 'password':password};
    doLogin(data);
}