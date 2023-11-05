function doLogin(data) {
    const resp = $.ajax({
        url: '/api/login',
        xhrFields: {withCredentials: true},
        type: 'post',
        dataType:'json',
        contentType:'application/json',
        processData: false,
        data: JSON.stringify(data),
        success: function(data) {
            console.log(data);
            if(data['success'] == "ok") {
                window.location = "/dashboard";
               }
               else {
                   document.getElementById("error").innerHTML = "Invalid Credentials";
               }
        }
    });
}