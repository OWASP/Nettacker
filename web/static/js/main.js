$(document).ready(function () {

    // a function to replace chars in string
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

    // login
    $("#send_session").click(function () {
        var key = "/session/set?key=" + $("#session_value").val();
        $.ajax({
            type: "GET",
            url: key,
            dataType: "text"
        }).done(function (res) {
            $("#set_session").hide();
            $("#success_key").removeClass("hidden");
            setTimeout("$(\"#success_key\").addClass(\"animated fadeOut\");", 5000);
            setTimeout("$(\"#success_key\").addClass(\"hidden\");", 5000);
            $("#logout_btn").removeClass("hidden");
            $("#logout_btn").show();
        }).fail(function (jqXHR, textStatus, errorThrown) {
            $("#set_session").hide();
            $("#failed_key").removeClass("hidden");
            setTimeout("$(\"#failed_key\").addClass(\"hidden\");", 5000);
            $("#set_session").show();
        });
    });


    // logout
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

    // home
    $("#home_btn").click(function () {
        $("#new_scan").addClass("hidden");
        $("#get_results").addClass("hidden");
        $("#crawler_area").addClass("hidden")
        $("#home").removeClass("hidden");
    });


    // new scan
    $("#new_scan_btn").click(function () {

        $.ajax({
            type: "GET",
            url: "/session/check",
            dataType: "text"
        }).done(function (res) {
            $("#home").addClass("hidden");
            $("#get_results").addClass("hidden");
            $("#crawler_area").addClass("hidden");
            $("#login_first").addClass("hidden");
            $("#new_scan").removeClass("hidden");
        }).fail(function (jqXHR, textStatus, errorThrown) {
            $("#home").addClass("hidden");
            $("#get_results").addClass("hidden");
            $("#crawler_area").addClass("hidden");
            $("#new_scan").addClass("hidden");
            $("#login_first").removeClass("hidden");
        });
    });

    // results crawler
    $("#results_btn").click(function () {
        $("#home").addClass("hidden");
        $("#new_scan").addClass("hidden");
        $("#crawler_area").addClass("hidden");
        $("#get_results").removeClass("hidden");
    });

    // hosts crawler
    $("#crawler_btn").click(function () {
        $("#home").addClass("hidden");
        $("#new_scan").addClass("hidden");
        $("#get_results").addClass("hidden");
        $("#crawler_area").removeClass("hidden");
    });

    // start tutorial
    $("#tutorial_btn").click(function () {
        if ($('#logout_btn').is(':hidden')) {
            var intro = introJs();
            intro.addSteps([
                {
                    element: document.querySelectorAll('#session_value')[0],
                    intro: "Please enter your API Key to proceed and click set session to proceed.",
                    position: 'right'
                }
            ]);
            intro.start();
        }
        else {
            var intro = introJs();
            intro.addSteps([
                {
                    intro: "Welcome to the OWASP Nettacker Web View Tutorial!",
                },
                {
                    element: document.querySelectorAll('#new_scan_btn')[0],
                    intro: "Click this button and select Next.",
                    position: 'right'
                },
                {
                    intro: "This is the area where you can perform new scans.",
                },
                {
                    element: document.querySelectorAll('#targets-entry')[0],
                    intro: "Enter your targets here. You enter a target and then press enter to enter a new target.",
                    position: 'right'
                },
                {
                    element: document.querySelectorAll('#scan_options_combined')[0],
                    intro: "Select the scans or brute forces you want to perform on your target.",
                    position: 'right'
                },
                {
                    element: document.querySelectorAll('#graph_flags')[0],
                    intro: "Select the output type of graph. The default is d3_tree_v2_graph.",
                    position: 'right'
                },
                {
                    element: document.querySelectorAll('#languages-entry')[0],
                    intro: "Select the language in which you want report in. We support a number of languages.",
                    position: 'right'
                },
                {
                    element: document.querySelectorAll('#log_in_file')[0],
                    intro: "Enter the location of the file you want your output in or leave it to the default value.",
                    position: 'right'
                },
                {
                    element: document.querySelectorAll('#advance')[0],
                    intro: "Click here to see some of the more advanced options.",
                    position: 'right'
                },
                {
                    element: document.querySelectorAll('#advance_options')[0],
                    intro: "These are some of the advanced options you can fiddle with.",
                    position: 'right'
                },
                {
                    element: document.querySelectorAll('#submit_new_scan')[0],
                    intro: "Click here to scan the targets with the selected options",
                    position: 'right'
                },
                {
                    element: document.querySelectorAll('#results_btn')[0],
                    intro: "Click here to view all the results sorted by the time they were performed.",
                    position: 'right'
                },
                {
                    element: document.querySelectorAll('#crawler_btn')[0],
                    intro: "Click here to view all the results sorted by the target on which it was performed.",
                    position: 'right'
                },
                {
                    element: document.querySelectorAll('#logout_btn')[0],
                    intro: "Click here to destroy your session.",
                    position: 'right'
                },
                {
                    intro: "This is the end of tutorial. If you have any questions, suggestions or " +
                    "feedback please contact us on Github. Thank you."
                }
            ]);
            intro.setOption('showProgress', true).setOption('showBullets', false).start();
        }
    });

    // submit new scan
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
            methods_args: $("#methods_args").val().replaceAll("\n", "&")

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

    var getUrlParameter = function getUrlParameter(sParam) {
        var sPageURL = decodeURIComponent(window.location.search.substring(1)),
            sURLVariables = sPageURL.split('&'),
            sParameterName,
            i;

        for (i = 0; i < sURLVariables.length; i++) {
            sParameterName = sURLVariables[i].split('=');

            if (sParameterName[0] === sParam) {
                return sParameterName[1] === undefined ? true : sParameterName[1];
            }
        }
    };


    var getUrlParameter = function getUrlParameter(sParam) {
        var sPageURL = decodeURIComponent(window.location.search.substring(1)),
            sURLVariables = sPageURL.split('&'),
            sParameterName,
            i;

        for (i = 0; i < sURLVariables.length; i++) {
            sParameterName = sURLVariables[i].split('=');

            if (sParameterName[0] === sParam) {
                return sParameterName[1] === undefined ? true : sParameterName[1];
            }
        }
    };

    // show scans in the html
    function show_scans(res) {
        res = JSON.parse(res);
        var HTMLData = "";
        var i;
        var id;
        var date;
        var scan_id;
        var report_filename;
        var events_num;
        var verbose;
        var api_flag;
        var report_type;
        var graph_flag;
        var category;
        var profile;
        var scan_method;
        var language;
        var scan_cmd;
        var ports;
        var flags = {
            "el": "gr",
            "fr": "fr",
            "en": "us",
            "nl": "nl",
            "ps": "ps",
            "tr": "tr",
            "de": "de",
            "ko": "kr",
            "it": "it",
            "ja": "jp",
            "fa": "ir",
            "hy": "am",
            "ar": "sa",
            "zh-cn": "cn",
            "vi": "vi",
            "ru": "ru",
            "hi": "in",
            "ur": "pk",
            "id": "id",
            "es": "es"
        };

        for (i = 0; i < res.length; i++) {
            id = res[i]["id"];
            date = res[i]["date"];
            scan_id = res[i]["scan_id"];
            report_filename = res[i]["report_filename"];
            events_num = res[i]["events_num"];
            verbose = res[i]["verbose"];
            api_flag = res[i]["api_flag"];
            report_type = res[i]["report_type"];
            graph_flag = res[i]["graph_flag"];
            category = res[i]["category"];
            profile = res[i]["profile"];
            scan_method = res[i]["scan_method"];
            language = res[i]["language"];
            scan_cmd = res[i]["scan_cmd"];
            ports = res[i]["ports"];
            HTMLData += "<a target='_blank' href=\"/results/get?id=" + id +
                "\" class=\"list-group-item list-group-item-action flex-column align-items-start\">\n" +
                "<div class=\"row\" ><div class=\"d-flex w-100\">\n" +
                "<h3  class=\"mb-1\">&nbsp;&nbsp;&nbsp;<span id=\"logintext\"\n" +
                "class=\"bold label label-primary\">" + id + "</span>" +
                "<small class=\"label label-info card-date\">" + date + "</small></h3>" +
                "</div></div>" + "<hr class='card-hr'>" +
                "<p class='mb-1  bold label label-default'>scan_id:" + scan_id + "</p><br>" +
                "<p class='mb-1  bold label label-info'>report_filename:" + report_filename + "</p><br>" +
                "<p class='mb-1 bold label label-success'>events_num:" + events_num + "</p><br>" +
                "<p class='mb-1 bold label label-danger'>ports:" + ports + "</p><br>" +
                "<p class='mb-1 bold label label-info'>category:" + category + "</p><br>" +
                "<p class='mb-1 bold label label-success'>profile:" + profile + "</p><br>" +
                "<p class='mb-1 bold label label-warning'>scan_method:" + scan_method + "</p><br>" +
                "<p class='mb-1 bold  label label-primary'>api_flag:" + api_flag + "</p><br>" +
                "<p class='mb-1 bold label label-warning'>verbose:" + verbose + "</p><br>" +
                "<p class='mb-1 bold label label-info'>report_type:" + report_type + "</p><br>" +
                "<p class='mb-1 bold label label-primary'>graph_flag:" + graph_flag + "</p><br>" +
                "<p class='mb-1 bold label label-success'>language:" + language + "</p>" +
                "<span class='card-flag flag-icon flag-icon-" + flags[language] + "'></span><br>" +
                "<p class='mb-1 bold label label-default'>scan_cmd:" + scan_cmd + "</p>" +
                "</p>\n </a>";
        }

        if (res["msg"] == "No more search results") {
            HTMLData = "<p class=\"mb-1\"> No more results to show!!</p>";
        }

        document.getElementById('scan_results').innerHTML = HTMLData;

    }


    function get_results_list(result_page) {
        $.ajax({
            type: "GET",
            url: "/results/get_list?page=" + result_page,
            dataType: "text"
        }).done(function (res) {
            $("#login_first").addClass("hidden");
            $("#scan_results").removeClass("hidden");
            $("#refresh_btn").removeClass("hidden");
            $("#nxt_prv_btn").removeClass("hidden");
            show_scans(res);
        }).fail(function (jqXHR, textStatus, errorThrown) {
            if (errorThrown == "UNAUTHORIZED") {
                $("#login_first").removeClass("hidden");
                $("#get_results").addClass("hidden");
                $("#refresh_btn").addClass("hidden");
                $("#nxt_prv_btn").addClass("hidden");
                $("#home").addClass("hidden");
                $("#crawler_area").addClass("hidden");
            }
            else {
                $("#login_first").addClass("hidden");
                $("#scan_results").removeClass("hidden");
                $("#refresh_btn").removeClass("hidden");
                $("#nxt_prv_btn").removeClass("hidden");
            }
        });
    }


    $("#results_btn").click(function () {
        result_page = 1;
        get_results_list(result_page);
    });

    $("#refresh_btn_update").click(function () {
        result_page = 1;
        get_results_list(result_page);
    });

    $("#refresh_btn_page").click(function () {
        get_results_list(result_page);
    });

    $("#previous_btn").click(function () {
        result_page = result_page - 1;
        if (result_page == 1) {
            $('#previous_btn').hide();
        }
        if (result_page == 2) {
            $('#previous_btn').show();
        }
        get_results_list(result_page);
    });

    $(".checkAll").click(function () {
        $(".checkbox").prop('checked', $(this).prop('checked'));
    });

    $(".checkbox-brute").click(function () {
        $(".checkbox-brute-module").prop('checked', $(this).prop('checked'));
    });

    $(".checkbox-scan").click(function () {
        $(".checkbox-scan-module").prop('checked', $(this).prop('checked'));
    });

    $(".checkbox-vulnerability").click(function () {
        $(".checkbox-vuln-module").prop('checked', $(this).prop('checked'));
    });

    $(".check-all-scans").click(function () {
        $(".checkbox-brute-module").prop('checked', $(this).prop('checked'));
        $(".checkbox-scan-module").prop('checked', $(this).prop('checked'));
        $(".checkbox-vuln-module").prop('checked', $(this).prop('checked'));
    });

    $('.checkbox-vuln-module').click(function () {
        if (!$(this).is(':checked')) {
            $('.checkAll').prop('checked', false);
            $('.checkbox-vulnerability').prop('checked', false);
            $('.check-all-scans').prop('checked', false);
        }
    });

    $('.checkbox-scan-module').click(function () {
        if (!$(this).is(':checked')) {
            $('.checkAll').prop('checked', false);
            $('.checkbox-scan').prop('checked', false);
            $('.check-all-scans').prop('checked', false);
        }
    });

    $('.checkbox-brute-module').click(function () {
        if (!$(this).is(':checked')) {
            $('.checkAll').prop('checked', false);
            $('.checkbox-brute').prop('checked', false);
            $('.check-all-scans').prop('checked', false);
        }
    });

    $("#next_btn").click(function () {
        result_page = result_page + 1;
        if (result_page == 1) {
            $('#previous_btn').hide();
        }
        if (result_page == 2) {
            $('#previous_btn').show();
        }
        get_results_list(result_page);
    });

    $("#advance").click(function () {
        $("#basic_options").addClass("hidden");
        $("#advance_options").removeClass("hidden");
    });

    $("#basic").click(function () {
        $("#advance_options").addClass("hidden");
        $("#basic_options").removeClass("hidden");
    });


    function show_crawler(res) {
        res = JSON.parse(res);
        var HTMLData = "";
        var host;
        var category;
        var html_categories;
        var description;
        var html_description;
        var open_ports;
        var html_open_ports;
        var scan_methods;
        var html_scan_methods;
        var j;

        for (i = 0; i < res.length; i++) {
            host = res[i]["host"];
            description = res[i]["info"]["descriptions"];
            open_ports = res[i]["info"]["open_ports"];
            scan_methods = res[i]["info"]["scan_methods"];
            category = res[i]["info"]["category"];
            html_categories = "";
            html_scan_methods = "";
            html_open_ports = "";
            html_description = "";
            for (j = 0; j < open_ports.length; j++) {
                html_open_ports += "<p class='mb-1 bold label label-warning'>open_port:" + open_ports[j] + "</p> ";
                if (j == 10) {
                    html_open_ports += "<p class='mb-1 bold label label-warning'>open_port: click to see more.</p> ";
                    break;
                }
            }
            for (j = 0; j < category.length; j++) {
                html_categories += "<p class='mb-1 bold label label-info'>category:" + category[j] + "</p> ";
                if (j == 10) {
                    html_categories += "<p class='mb-1 bold label label-info'>category: click to see more.</p> ";
                    break;
                }
            }
            html_scan_methods = "";
            for (j = 0; j < scan_methods.length; j++) {
                html_scan_methods += "<p class='mb-1 bold label label-primary'>scan_method:" + scan_methods[j] + "</p> ";
                if (j == 10) {
                    html_scan_methods += "<p class='mb-1 bold label label-primary'>scan_method: click to see more.</p> ";
                    break;
                }
            }
            for (j = 0; j < description.length; j++) {
                html_description += "<p class='mb-1 bold label label-success'>description:" + description[j] + "</p> ";
                if (j == 10) {
                    html_description += "<p class='mb-1 bold label label-success'>description: click to see more.</p> ";
                    break;
                }
            }

            HTMLData += "<a target='_blank' href=\"/logs/get_html?host=" + host + "\" class=\"list-group-item list-group-item-action flex-column align-items-start\">\n" +
                "<div class=\"row\" ><div class=\"d-flex w-100 text-justify justify-content-between\">\n" +
                "<h3  class=\"mb-1\">&nbsp;&nbsp;&nbsp;<span id=\"logintext\"\n" +
                "class=\"bold label label-danger\">" + host + "</span></h3>\n" +
                "</div></div>\n" + "<p class=\"mb-1\"> " + html_categories + html_scan_methods +
                html_open_ports + html_description +
                "</p>\n </a>";
        }

        if (res["msg"] == "No more search results") {
            HTMLData = "<p class=\"mb-1\"> No more results to show!!</p>";
        }

        document.getElementById('crawl_results').innerHTML = HTMLData;

    }


    function get_crawler_list(crawler_page) {
        $.ajax({
            type: "GET",
            url: "/logs/search?q=" + $("#search_data").val() + "&page=" + crawler_page,
            dataType: "text"
        }).done(function (res) {
            $("#login_first").addClass("hidden");
            $("#crawl_results").removeClass("hidden");
            $("#crw_refresh_btn").removeClass("hidden");
            $("#crw_nxt_prv_btn").removeClass("hidden");
            show_crawler(res);
        }).fail(function (jqXHR, textStatus, errorThrown) {
            if (errorThrown == "UNAUTHORIZED") {
                $("#login_first").removeClass("hidden");
                $("#crawl_results").addClass("hidden");
                $("#crw_refresh_btn").addClass("hidden");
                $("#crw_nxt_prv_btn").addClass("hidden");
                $("#home").addClass("hidden");
                $("#crawler_area").addClass("hidden");
            }
            else {
                $("#login_first").addClass("hidden");
                $("#crawl_results").removeClass("hidden");
                $("#crw_refresh_btn").removeClass("hidden");
                $("#crw_nxt_prv_btn").removeClass("hidden");
            }
        });
    }


    $("#crawler_btn").click(function () {
        crawler_page = 1;
        get_crawler_list(crawler_page);
    });

    $("#crw_refresh_btn_update").click(function () {
        crawler_page = 1;
        get_crawler_list(crawler_page);
    });

    $("#crw_refresh_btn_page").click(function () {
        get_crawler_list(crawler_page);
    });

    $("#crw_previous_btn").click(function () {
        crawler_page = crawler_page - 1;
        if (crawler_page == 1) {
            $('#crw_previous_btn').hide();
        }
        if (crawler_page == 2) {
            $('#crw_previous_btn').show();
        }
        get_crawler_list(crawler_page);
    });

    $("#crw_next_btn").click(function () {
        crawler_page = crawler_page + 1;
        if (crawler_page == 1) {
            $('#crw_previous_btn').hide();
        }
        if (crawler_page == 2) {
            $('#crw_previous_btn').show();
        }
        get_crawler_list(crawler_page);
    });


    function _query_search() {

        $.ajax({
            type: "GET",
            url: "/logs/search?q=" + $("#search_data").val(),
            dataType: "text"
        }).done(function (res) {
            $("#login_first").addClass("hidden");
            $("#crawl_results").removeClass("hidden");
            $("#crw_refresh_btn").removeClass("hidden");
            $("#crw_nxt_prv_btn").removeClass("hidden");
            show_crawler(res);
        }).fail(function (jqXHR, textStatus, errorThrown) {
            if (errorThrown == "UNAUTHORIZED") {
                $("#login_first").removeClass("hidden");
                $("#crawl_results").addClass("hidden");
                $("#crw_refresh_btn").addClass("hidden");
                $("#crw_nxt_prv_btn").addClass("hidden");
                $("#home").addClass("hidden");
                $("#crawler_area").addClass("hidden");

            }
            else {
                $("#login_first").addClass("hidden");
                $("#crawl_results").removeClass("hidden");
                $("#crw_refresh_btn").removeClass("hidden");
                $("#crw_nxt_prv_btn").removeClass("hidden");
            }
        });

    }

    $("#search_btn").click(function () {
        _query_search();
    });

    $("#search_data").keyup(function (event) {
        if (event.keyCode === 13) {
            _query_search();
        }
    });

});