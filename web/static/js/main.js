// check for session key
$(document).ready(function () {
    // hide set session key
    $("#set_session").hide();

    //check session key
    $.ajax({
        type: "GET",
        url: "/session/check",
        dataType: "text"
    }).done(function (res) {
        // Your `success` code
    }).fail(function (jqXHR, textStatus, errorThrown) {
        $("#set_session").show();
    });

    // set session key
    $("#session_value").keyup(function (event) {
        if (event.keyCode === 13) {
            $("#send_session").click();
        }
    });
    $("#send_session").click(function () {
        var key = "/session/set?key=" + $('#session_value').val();
        $.ajax({
            type: "GET",
            url: key,
            dataType: "text"
        }).done(function (res) {
            $("#set_session").hide();
            $("#success_key").removeClass("hidden");
            setTimeout("$(\"#success_key\").addClass(\"hidden\");", 1000);
        }).fail(function (jqXHR, textStatus, errorThrown) {
            $("#set_session").hide();
            $("#failed_key").removeClass("hidden");
            setTimeout("$(\"#failed_key\").addClass(\"hidden\");", 1000);
            $("#set_session").show();
        });
    });

});

function check_api_session() {

}