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
        $("#set_session").addClass("hidden");
        $("#set_session").hide();
        $("#logout_btn").removeClass("hidden");
        $("#logout_btn").show();

    }).fail(function (jqXHR, textStatus, errorThrown) {
        $("#set_session").removeClass("hidden");
        $("#set_session").show();
        $("#logout_btn").addClass("hidden");
        $("#logout_btn").hide();
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
            setTimeout("$(\"#success_key\").addClass(\"animated fadeOut\");", 1000);
            setTimeout("$(\"#success_key\").addClass(\"hidden\");", 1500);
            $("#logout_btn").removeClass("hidden");
            $("#logout_btn").show();
        }).fail(function (jqXHR, textStatus, errorThrown) {
            $("#set_session").hide();
            $("#failed_key").removeClass("hidden");
            setTimeout("$(\"#failed_key\").addClass(\"hidden\");", 2000);
            $("#set_session").show();
        });
    });

    $("#logout_btn").click(function () {
        $.ajax({
            type: "GET",
            url: "/session/kill",
            dataType: "text"
        }).done(function (res) {
            $("#session_value").val("");
            $("#logout_btn").addClass("hidden");
            $("#logout_btn").hide();
            $("#set_session").removeClass("hidden");
            $("#set_session").show();
            $("#logout_success").removeClass("hidden");
            setTimeout("$(\"#logout_success\").addClass(\"animated fadeOut\");", 1000);
            setTimeout("$(\"#logout_success\").addClass(\"hidden\");", 1500);
        }).fail(function (jqXHR, textStatus, errorThrown) {
            // codes
        });
    });


    $("#home_btn").click(function () {
        $("#new_scan").addClass("hidden");
        $("#home").removeClass("hidden");

    });

    $("#new_scan_btn").click(function () {
        $("#home").addClass("hidden");
        $("#new_scan").removeClass("hidden");


    });

});
