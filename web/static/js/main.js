// check for session key
$(document).ready(function () {
    String.prototype.replaceAll = function (search, replacement) {
        var target = this;
        return target.replace(new RegExp(search, 'g'), replacement);
    };
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
        var key = "/session/set?key=" + $("#session_value").val();
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
        $("#get_results").addClass("hidden");
        $("#home").removeClass("hidden");
    });

    $("#new_scan_btn").click(function () {
        $("#home").addClass("hidden");
        $("#get_results").addClass("hidden");
        $("#new_scan").removeClass("hidden");
    });

    $("#results_btn").click(function () {
        $("#home").addClass("hidden");
        $("#new_scan").addClass("hidden");
        $("#get_results").removeClass("hidden");
    });




    $("#submit_new_scan").click(function () {

        // set variables
        // check ranges
        if (document.getElementById('check_ranges').checked) {
            var p_1 = true;
        } else {
            var p_1 = false;
        }
        // ping before scan
        if (document.getElementById('ping_flag').checked) {
            var p_2 = true;
        } else {
            var p_2 = false;
        }
        // subdomains
        if (document.getElementById('check_subdomains').checked) {
            var p_3 = true;
        } else {
            var p_3 = false;
        }
        // profiles
        var p = []
        var n = 0;
        $('#profile input:checked').each(function () {
            p[n] = this.id;
            n += 1;
        });
        var profile = p.join(",");

        // scan_methods
        n = 0;
        sm = []
        $('#scan_method input:checked').each(function () {
            sm[n] = this.id;
            n += 1;
        });
        var scan_method = sm.join(",")
        // language
        var language = "";
        $('#languages option:selected').each(function () {
            language = this.id;
        });

        // graph_flag
        var graph_flag = "";
        $('#graph_flags input:checked').each(function () {
            graph_flag = this.id;
        });


        // build post data
        var tmp_data = {
            targets: $("#targets").val(),
            profile: profile,
            scan_method: scan_method,
            graph_flag: graph_flag,
            language: language,
            log_in_file: $("#log_in_file").val(),
            check_ranges: p_1,
            check_subdomains: p_3,
            ping_flag: p_2,
            thread_number: $("#thread_number").val(),
            thread_number_host: $("#thread_number_host").val(),
            retries: $("#retries").val(),
            time_sleep: $("#time_sleep").val(),
            timeout_sec: $("#timeout_sec").val(),
            verbose_level: $("#verbose_level").val(),
            ports: $("#ports").val(),
            socks_proxy: $("#socks_proxy").val(),
            users: $("#users").val(),
            passwds: $("#passwds").val(),
            methods_args: $("#methods_args").val().replaceAll("\n", "&"),

        };

        // replace "" with null
        var key = "";
        var data = {};
        for (key in tmp_data) {
            if (tmp_data[key] != "" && tmp_data[key] != false && tmp_data[key] != null) {
                data[key] = tmp_data[key];
            }
        }

        $.ajax({
            type: "POST",
            url: "/new/scan",
            data: data,
        }).done(function (res) {
            var results = JSON.stringify(res);
            results = results.replaceAll(",", ",<br>");
            document.getElementById('success_msg').innerHTML = results;
            $("#success_request").removeClass("hidden");
            setTimeout("$(\"#success_request\").addClass(\"animated fadeOut\");", 5000);
            setTimeout("$(\"#success_request\").addClass(\"hidden\");", 6000);
            $("#success_request").removeClass("animated fadeOut");
        }).fail(function (jqXHR, textStatus, errorThrown) {
            document.getElementById('error_msg').innerHTML = jqXHR.responseText;
            if (errorThrown == "BAD REQUEST") {
                $("#failed_request").removeClass("hidden");
                setTimeout("$(\"#failed_request\").addClass(\"hidden\");", 5000);
            }
            if (errorThrown == "UNAUTHORIZED") {
                $("#failed_request").removeClass("hidden");
                setTimeout("$(\"#failed_request\").addClass(\"hidden\");", 5000);
            }
        });

    });


    $("#results_btn").click(function () {
        $.ajax({
            type: "GET",
            url: "/results/get",
            dataType: "text"
        }).done(function (res) {
            $("#login_first").addClass("hidden");
            $("#scan_results").removeClass("hidden");
            document.getElementById('success_msg').innerHTML = res;
        }).fail(function (jqXHR, textStatus, errorThrown) {
            $("#login_first").removeClass("hidden");
            $("#scan_results").addClass("hidden");
        });
    });
// <a href="#" class="list-group-item list-group-item-action flex-column align-items-start active">
//         <div class="d-flex w-100 justify-content-between">
//         <h4 class="mb-1">List group item heading</h4>
//     <small>3 days ago</small>
//     </div>
//     <p class="mb-1">Donec id elit non mi porta gravida at eget metus. Maecenas sed diam eget risus varius
//     blandit.</p>
//     <small>Donec id elit non mi porta.</small>
//     </a>
});

