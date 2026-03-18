$(document).ready(function () {
  // a function to replace chars in string
  String.prototype.replaceAll = function (search, replacement) {
    var target = this;
    return target.replace(new RegExp(search, "g"), replacement);
  };

  // hide set session key
  $("#set_session").hide();

  //check session key
  $.ajax({
    type: "GET",
    url: "/session/check",
    dataType: "text",
  })
    .done(function (res) {
      $("#set_session").addClass("hidden");
      $("#set_session").hide();
      $("#logout_btn").removeClass("hidden");
      $("#logout_btn").show();
    })
    .fail(function (jqXHR, textStatus, errorThrown) {
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
      dataType: "text",
    })
      .done(function (res) {
        $("#set_session").hide();
        $("#success_key").removeClass("hidden");
        // FIX #7: setTimeout with functions instead of strings
        // FIX #6: removeClass("animated fadeOut") moved inside the later timeout so fade works
        setTimeout(function () { $("#success_key").addClass("animated fadeOut"); }, 5000);
        setTimeout(function () { $("#success_key").addClass("hidden").removeClass("animated fadeOut"); }, 6000);
        $("#logout_btn").removeClass("hidden");
        $("#logout_btn").show();
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        $("#set_session").hide();
        $("#failed_key").removeClass("hidden");
        setTimeout(function () { $("#failed_key").addClass("hidden"); }, 5000); // FIX #7
        $("#set_session").show();
      });
  });

  // logout
  $("#logout_btn").click(function () {
    $.ajax({
      type: "GET",
      url: "/session/kill",
      dataType: "text",
    })
      .done(function (res) {
        $("#session_value").val("");
        $("#logout_btn").addClass("hidden");
        $("#logout_btn").hide();
        $("#set_session").removeClass("hidden");
        $("#set_session").show();
        $("#logout_success").removeClass("hidden");
        setTimeout(function () { $("#logout_success").addClass("animated fadeOut"); }, 1000); // FIX #7
        setTimeout(function () { $("#logout_success").addClass("hidden").removeClass("animated fadeOut"); }, 1500); // FIX #7
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        // codes
      });
  });

  // home
  $("#home_btn").click(function () {
    $("#new_scan").addClass("hidden");
    $("#get_results").addClass("hidden");
    $("#crawler_area").addClass("hidden");
    $("#compare_area").addClass("hidden");
    $("#home").removeClass("hidden");
  });

  // new scan
  $("#new_scan_btn").click(function () {
    $.ajax({
      type: "GET",
      url: "/session/check",
      dataType: "text",
    })
      .done(function (res) {
        $("#home").addClass("hidden");
        $("#get_results").addClass("hidden");
        $("#crawler_area").addClass("hidden");
        $("#login_first").addClass("hidden");
        $("#compare_area").addClass("hidden");
        $("#new_scan").removeClass("hidden");
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        $("#home").addClass("hidden");
        $("#get_results").addClass("hidden");
        $("#crawler_area").addClass("hidden");
        $("#new_scan").addClass("hidden");
        $("#compare_area").addClass("hidden");
        $("#login_first").removeClass("hidden");
      });
  });

  // results crawler
  $("#results_btn").click(function () {
    $("#home").addClass("hidden");
    $("#new_scan").addClass("hidden");
    $("#crawler_area").addClass("hidden");
    $("#compare_area").addClass("hidden");
    $("#get_results").removeClass("hidden");
  });

  // hosts crawler
  $("#crawler_btn").click(function () {
    $("#home").addClass("hidden");
    $("#new_scan").addClass("hidden");
    $("#get_results").addClass("hidden");
    $("#compare_area").addClass("hidden");
    $("#crawler_area").removeClass("hidden");
  });

  // FIX #1: Removed the first duplicate #compare_btn handler that lacked session check.
  // The single handler below performs the session check and handles both success/fail correctly.
  $("#compare_btn").click(function () {
    $.ajax({
      type: "GET",
      url: "/session/check",
      dataType: "text",
    })
      .done(function (res) {
        $("#home").addClass("hidden");
        $("#new_scan").addClass("hidden");
        $("#get_results").addClass("hidden");
        $("#crawler_area").addClass("hidden");
        $("#login_first").addClass("hidden");
        $("#compare_area").removeClass("hidden");
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        $("#home").addClass("hidden");
        $("#get_results").addClass("hidden");
        $("#crawler_area").addClass("hidden");
        $("#new_scan").addClass("hidden");
        $("#compare_area").addClass("hidden");
        $("#login_first").removeClass("hidden");
      });
  });

  // Create the compare report
  $("#create_compare_report").click(function () {
    var tmp_data = {
      scan_id_first: $("#scan_id_first").val(),
      scan_id_second: $("#scan_id_second").val(),
      compare_report_path: $("#compare_report_path").val(),
    };
    var key = "";
    var data = {};
    for (key in tmp_data) {
      if (
        tmp_data[key] != "" &&
        tmp_data[key] != false &&
        tmp_data[key] != null
      ) {
        data[key] = tmp_data[key];
      }
    }
    $.ajax({
      type: "POST",
      url: "/compare/scans",
      data: data,
    })
      .done(function (response, textStatus, jqXHR) {
        if (response.status === "success") {
          $("#success_report").removeClass("hidden");
          // FIX #6 & #7: use function callbacks; removeClass deferred so fade actually plays
          setTimeout(function () { $("#success_report").addClass("animated fadeOut"); }, 5000);
          setTimeout(function () { $("#success_report").addClass("hidden").removeClass("animated fadeOut"); }, 6000);
        } else {
          document.getElementById("report_error_msg").innerHTML = response.message;
          $("#failed_report").removeClass("hidden");
          setTimeout(function () { $("#failed_report").addClass("hidden"); }, 5000); // FIX #7
        }
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        var errorMessage = "An error occurred while comparing scans.";
        if (jqXHR.responseJSON && jqXHR.responseJSON.msg) {
          errorMessage = jqXHR.responseJSON.msg;
        }
        document.getElementById("report_error_msg").innerHTML = errorMessage;
        $("#failed_report").removeClass("hidden");
        setTimeout(function () { $("#failed_report").addClass("hidden"); }, 5000); // FIX #7
      });
  });

  // start tutorial
  $("#tutorial_btn").click(function () {
    if ($("#logout_btn").is(":hidden")) {
      var intro = introJs();
      intro.addSteps([
        {
          element: document.querySelectorAll("#session_value")[0],
          intro:
            "Please enter your API Key to proceed and click set session to proceed.",
          position: "right",
        },
      ]);
      intro.start();
    } else {
      var intro = introJs();
      intro.addSteps([
        {
          intro: "Welcome to the OWASP Nettacker Web View Tutorial!",
        },
        {
          element: document.querySelectorAll("#new_scan_btn")[0],
          intro: "Click this button and select Next.",
          position: "right",
        },
        {
          intro: "This is the area where you can perform new scans.",
        },
        {
          element: document.querySelectorAll("#targets-entry")[0],
          intro:
            "Enter your targets here. You enter a target and then press enter to enter a new target.",
          position: "right",
        },
        {
          element: document.querySelectorAll("#scan_options_combined")[0],
          intro:
            "Select the scans or brute forces you want to perform on your target.",
          position: "right",
        },
        {
          element: document.querySelectorAll("#graph_name")[0],
          intro:
            "Select the output type of graph. The default is d3_tree_v2_graph.",
          position: "right",
        },
        {
          element: document.querySelectorAll("#languages-entry")[0],
          intro:
            "Select the language in which you want report in. We support a number of languages.",
          position: "right",
        },
        {
          element: document.querySelectorAll("#output_file")[0],
          intro:
            "Enter the location of the file you want your output in or leave it to the default value.",
          position: "right",
        },
        {
          element: document.querySelectorAll("#advance")[0],
          intro: "Click here to see some of the more advanced options.",
          position: "right",
        },
        {
          element: document.querySelectorAll("#advance_options")[0],
          intro: "These are some of the advanced options you can fiddle with.",
          position: "right",
        },
        {
          element: document.querySelectorAll("#submit_new_scan")[0],
          intro: "Click here to scan the targets with the selected options",
          position: "right",
        },
        {
          element: document.querySelectorAll("#results_btn")[0],
          intro:
            "Click here to view all the results sorted by the time they were performed.",
          position: "right",
        },
        {
          element: document.querySelectorAll("#crawler_btn")[0],
          intro:
            "Click here to view all the results sorted by the target on which it was performed.",
          position: "right",
        },
        {
          element: document.querySelectorAll("#compare_btn_ul")[0],
          intro:
            "Click here to compare two scans and generate a compare report",
          position: "right",
        },
        {
          element: document.querySelectorAll("#logout_btn")[0],
          intro: "Click here to destroy your session.",
          position: "right",
        },
        {
          intro:
            "This is the end of tutorial. If you have any questions, suggestions or " +
            "feedback please contact us on Github. Thank you.",
        },
      ]);
      intro
        .setOption("showProgress", true)
        .setOption("showBullets", false)
        .start();
    }
  });

  // submit new scan
  $("#submit_new_scan").click(function () {
    // set variables
    // check ranges
    var p_1 = document.getElementById("scan_ip_range").checked ? true : false;
    // ping before scan
    var p_2 = document.getElementById("ping_before_scan").checked ? true : false;
    // subdomains
    var p_3 = document.getElementById("scan_subdomains").checked ? true : false;

    var skip_service_discovery = document.getElementById("skip_service_discovery").checked ? true : false;

    // profiles
    var p = [];
    var n = 0;
    $("#profiles input:checked").each(function () {
      if (this.id !== "all_profiles") {
        p[n] = this.id;
        n += 1;
      }
    });
    var profiles = p.join(",");

    // scan_methods
    n = 0;
    var sm = [];
    $("#selected_modules input:checked").each(function () {
      sm[n] = this.id;
      n += 1;
    });
    var selected_modules = sm.join(",");

    // language
    var language = "";
    $("#languages option:selected").each(function () {
      language = this.id;
    });

    // graph_name
    var graph_name = "";
    $("#graph_name input:checked").each(function () {
      graph_name = this.id;
    });

    // build post data
    var tmp_data = {
      targets: $("#targets").val(),
      profiles: profiles,
      selected_modules: selected_modules,
      graph_name: graph_name,
      language: language,
      report_path_filename: $("#output_file").val(),
      scan_ip_range: p_1,
      scan_subdomains: p_3,
      ping_before_scan: p_2,
      thread_per_host: $("#thread_per_host").val(),
      parallel_host_scan: $("#parallel_host_scan").val(),
      retries: $("#retries").val(),
      time_sleep_between_requests: $("#time_sleep_between_requests").val(),
      timeout: $("#timeout").val(),
      verbose_mode: $("#verbose_mode").val(),
      ports: $("#ports").val(),
      socks_proxy: $("#socks_proxy").val(),
      usernames: $("#usernames").val(),
      passwords: $("#passwords").val(),
      skip_service_discovery: skip_service_discovery,
      excluded_ports: $("#exclude_ports").val(),
      http_header: $("#http_headers").val(),
    };

    // replace "" with null
    var key = "";
    var data = {};
    for (key in tmp_data) {
      if (
        tmp_data[key] != "" &&
        tmp_data[key] != false &&
        tmp_data[key] != null
      ) {
        data[key] = tmp_data[key];
      }
    }

    $.ajax({
      type: "POST",
      url: "/new/scan",
      data: data,
    })
      .done(function (res) {
        var results = JSON.stringify(res);
        results = results.replaceAll(",", ",<br>");
        document.getElementById("success_msg").innerHTML = results;
        $("#success_request").removeClass("hidden");
        // FIX #6 & #7: use function callbacks; removeClass deferred so fade actually plays
        setTimeout(function () { $("#success_request").addClass("animated fadeOut"); }, 5000);
        setTimeout(function () { $("#success_request").addClass("hidden").removeClass("animated fadeOut"); }, 6000);
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        document.getElementById("error_msg").innerHTML = jqXHR.responseText;
        if (errorThrown == "BAD REQUEST") {
          $("#failed_request").removeClass("hidden");
          setTimeout(function () { $("#failed_request").addClass("hidden"); }, 5000); // FIX #7
        }
        if (errorThrown == "UNAUTHORIZED") {
          $("#failed_request").removeClass("hidden");
          setTimeout(function () { $("#failed_request").addClass("hidden"); }, 5000); // FIX #7
        }
      });
  });

  // FIX #2: Removed duplicate getUrlParameter definition — keeping only one copy.
  var getUrlParameter = function getUrlParameter(sParam) {
    var sPageURL = decodeURIComponent(window.location.search.substring(1)),
      sURLVariables = sPageURL.split("&"),
      sParameterName,
      i;

    for (i = 0; i < sURLVariables.length; i++) {
      sParameterName = sURLVariables[i].split("=");

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

    for (i = 0; i < res.length; i++) {
      id = res[i]["id"];
      date = res[i]["date"];
      scan_id = res[i]["scan_id"];
      HTMLData +=
        "<a target='_blank' href=\"/results/get?id=" +
        id +
        '" class="list-group-item list-group-item-action flex-column align-items-start">\n' +
        '<div class="row" ><div class="d-flex w-100">\n' +
        '<h3  class="mb-1">&nbsp;&nbsp;&nbsp;<span id="logintext"\n' +
        'class="bold label label-primary">' +
        id +
        "</span>" +
        '<small class="label label-info card-date">' +
        date +
        "</small></h3>" +
        "</div></div>" +
        "<hr class='card-hr'>" +
        "<p class='mb-1  bold label label-default'>scan_id:" +
        scan_id +
        "</p><br>" +
        '<button class="mb-1 bold label card-date"><a href="/results/get_json?id=' +
        id +
        '">Get JSON</a></button>' +
        '<button class="mb-1 bold label card-date"><a href="/results/get_csv?id=' +
        id +
        '">Get CSV </a></button>';
    }

    if (res["msg"] == "No more search results") {
      HTMLData = '<p class="mb-1"> No more results to show!!</p>';
    }

    document.getElementById("scan_results").innerHTML = HTMLData;
  }

  function get_results_list(result_page) {
    $.ajax({
      type: "GET",
      url: "/results/get_list?page=" + result_page,
      dataType: "text",
    })
      .done(function (res) {
        $("#login_first").addClass("hidden");
        $("#scan_results").removeClass("hidden");
        $("#refresh_btn").removeClass("hidden");
        $("#nxt_prv_btn").removeClass("hidden");
        show_scans(res);
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        if (errorThrown == "UNAUTHORIZED") {
          $("#login_first").removeClass("hidden");
          $("#get_results").addClass("hidden");
          $("#refresh_btn").addClass("hidden");
          $("#nxt_prv_btn").addClass("hidden");
          $("#home").addClass("hidden");
          $("#crawler_area").addClass("hidden");
          $("#compare_area").addClass("hidden");
        } else {
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
      $("#previous_btn").hide();
    }
    if (result_page == 2) {
      $("#previous_btn").show();
    }
    get_results_list(result_page);
  });

  $(".checkAll").click(function () {
    $(".checkbox").prop("checked", $(this).prop("checked"));
  });

  $(".checkbox-brute").click(function () {
    $(".checkbox-brute-module").prop("checked", $(this).prop("checked"));
  });

  $(".checkbox-scan").click(function () {
    $(".checkbox-scan-module").prop("checked", $(this).prop("checked"));
  });

  $(".checkbox-vulnerability").click(function () {
    $(".checkbox-vuln-module").prop("checked", $(this).prop("checked"));
  });

  $(".check-all-profiles").click(function () {
    $("#profiles input[type='checkbox']").not(this).prop("checked", $(this).prop("checked"));
  });

  $(".check-all-scans").click(function () {
    $(".checkbox-brute-module").prop("checked", $(this).prop("checked"));
    $(".checkbox-scan-module").prop("checked", $(this).prop("checked"));
    $(".checkbox-vuln-module").prop("checked", $(this).prop("checked"));
  });

  $(".checkbox-vuln-module").click(function () {
    if (!$(this).is(":checked")) {
      $(".checkAll").prop("checked", false);
      $(".checkbox-vulnerability").prop("checked", false);
      $(".check-all-scans").prop("checked", false);
    }
  });

  $(".checkbox-scan-module").click(function () {
    if (!$(this).is(":checked")) {
      $(".checkAll").prop("checked", false);
      $(".checkbox-scan").prop("checked", false);
      $(".check-all-scans").prop("checked", false);
    }
  });

  $(".checkbox-brute-module").click(function () {
    if (!$(this).is(":checked")) {
      $(".checkAll").prop("checked", false);
      $(".checkbox-brute").prop("checked", false);
      $(".check-all-scans").prop("checked", false);
    }
  });

  $("#next_btn").click(function () {
    result_page = result_page + 1;
    if (result_page == 1) {
      $("#previous_btn").hide();
    }
    if (result_page == 2) {
      $("#previous_btn").show();
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

  function obsKeysToString(o, k, sep) {
    return k.map(function (key) { return o[key]; }).filter(function (v) { return v; }).join(sep);
  }

  function filter_large_content(content, filter_rate) {
    if (content == undefined) {
      return content;
    }
    if (content.length <= filter_rate) {
      return content;
    } else {
      filter_rate -= 1;
      var filter_index = filter_rate;
      for (var i = 0; i < content.substring(filter_rate).length; i++) {
        if (content.substring(i, i + 1) == " ") {
          return content.substring(0, filter_index) + "... [see the full content in the report]";
        } else {
          filter_index += 1;
        }
      }
      return content;
    }
  }

  function show_crawler(res) {
    res = JSON.parse(res);
    var HTMLData = "";

    for (var i = 0; i < res.length; i++) {
      var target      = res[i]["target"];
      var module_name = res[i]["info"]["module_name"];
      var events      = res[i]["info"]["event"];
      var ports       = res[i]["info"]["port"];
      var dates       = res[i]["info"]["date"];

      var html_meta   = "";
      var html_events = "";

      // Date
      if (dates && dates.length > 0) {
        html_meta += "<p class='mb-1 bold label label-default'>date: " + dates[0] + "</p> ";
      }

      // Modules
      for (var j = 0; j < module_name.length; j++) {
        html_meta += "<p class='mb-1 bold label label-info'>module: " + module_name[j] + "</p> ";
      }

      // Ports
      if (ports && ports.length > 0) {
        html_meta += "<p class='mb-1 bold label label-primary'>ports: " + ports.join(", ") + "</p> ";
      }

      html_meta += "<br>";

      // Events — split on 'conditions: ' safely, avoids undefined when key is absent
      for (var k = 0; k < events.length; k++) {
        var parts      = events[k].split("conditions: ");
        var event_text = filter_large_content(parts[0], 100);
        var cond_text  = parts.length > 1 ? filter_large_content(parts[1], 100) : "";

        html_events += "<p class='mb-1 bold label label-success'>event: " + event_text + "</p> ";
        if (cond_text) {
          html_events += "<p class='mb-1 bold label label-warning'>conditions: " + cond_text + "</p> ";
        }
        html_events += "<br>";
      }

      HTMLData +=
        '<div class="row myBox"><div class="d-flex w-100 text-justify justify-content-between">\n' +
        '<button class="btn btn-primary" style="margin-right: 1rem">' +
        '<a target="_blank" style="color: white" href="/logs/get_html?target=' + target + '">' + target + "</a>" +
        "</button>" +
        '<button class="btn btn-secondary" style="margin-right: 1rem">' +
        '<a href="/logs/get_json?target=' + target + '">Get JSON</a>' +
        "</button>" +
        '<button class="btn btn-secondary">' +
        '<a href="/logs/get_csv?target=' + target + '">Get CSV</a>' +
        "</button>" +
        "</div>\n" +
        '<p class="mb-1">' + html_meta + html_events + "</p></div>";
    }

    if (res["msg"] == "No more search results") {
      HTMLData = '<p class="mb-1">No more results to show.</p>';
    }

    document.getElementById("crawl_results").innerHTML = HTMLData;
  }

  function clearPaginationButtons() {
    $(".page_number_btn").remove();
  }

  // FIX #5: Removed duplicate .toggle() calls — each button toggled only once.
  function updatePaginationControls(totalPages, currentPage) {
    clearPaginationButtons();

    var startPage = Math.max(currentPage - 2, 1);
    var endPage = Math.min(startPage + 4, totalPages);

    for (var i = startPage; i <= endPage; i++) {
      (function (pageNum) {
        var pageBtn = $("<button>").addClass("page_number_btn").text(pageNum);
        if (pageNum === currentPage) {
          pageBtn.addClass("active");
        }
        pageBtn.insertBefore("#crw_next_btn");
        pageBtn.click(function () {
          crawler_page = pageNum;
          get_crawler_list(pageNum);
        });
      })(i);
    }

    $("#crw_first_btn").toggle(currentPage > 1);
    $("#crw_previous_btn").toggle(currentPage > 1);
    $("#crw_next_btn").toggle(currentPage < totalPages);
    $("#crw_last_btn").toggle(currentPage < totalPages);
  }

  // FIX #4: totalPages hoisted to outer scope so crw_last_btn handler can access it.
  var crawlerTotalPages = 1;

  $("#crw_first_btn").click(function () {
    if (crawler_page > 1) {
      crawler_page = 1;
      get_crawler_list(crawler_page);
    }
  });

  $("#crw_last_btn").click(function () {
    if (crawler_page < crawlerTotalPages) { // FIX #4: use hoisted variable
      crawler_page = crawlerTotalPages;
      get_crawler_list(crawler_page);
    }
  });

  function get_crawler_list(crawler_page) {
    $.ajax({
      type: "GET",
      url: "/logs/search?q=" + $("#search_data").val() + "&page=" + crawler_page,
      dataType: "text",
    })
      .done(function (res) {
        // FIX #3: parse JSON first, then use array length — not raw string length
        var parsed = JSON.parse(res);
        crawlerTotalPages = Math.ceil(parsed.length / 10); // FIX #3 & #4
        $("#login_first").addClass("hidden");
        $("#crawl_results").removeClass("hidden");
        $("#crw_refresh_btn").removeClass("hidden");
        $("#crw_nxt_prv_btn").removeClass("hidden");
        $("#current_page_number").text(crawler_page);
        $("#total_pages").text(crawlerTotalPages);
        // Pass the already-parsed data; show_crawler re-parses so pass as string
        show_crawler(res);
        // FIX #5: updatePaginationControls handles show/hide — removed redundant manual toggling below
        updatePaginationControls(crawlerTotalPages, crawler_page);
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        if (errorThrown == "UNAUTHORIZED") {
          $("#login_first").removeClass("hidden");
          $("#crawl_results").addClass("hidden");
          $("#crw_refresh_btn").addClass("hidden");
          $("#crw_nxt_prv_btn").addClass("hidden");
          $("#home").addClass("hidden");
          $("#crawler_area").addClass("hidden");
          $("#compare_area").addClass("hidden");
        } else {
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
      $("#crw_previous_btn").hide();
    }
    if (crawler_page == 2) {
      $("#crw_previous_btn").show();
    }
    get_crawler_list(crawler_page);
  });

  $("#crw_next_btn").click(function () {
    crawler_page = crawler_page + 1;
    if (crawler_page == 1) {
      $("#crw_previous_btn").hide();
    }
    if (crawler_page == 2) {
      $("#crw_previous_btn").show();
    }
    get_crawler_list(crawler_page);
  });

  function _query_search() {
    $.ajax({
      type: "GET",
      url: "/logs/search?q=" + $("#search_data").val(),
      dataType: "text",
    })
      .done(function (res) {
        $("#login_first").addClass("hidden");
        $("#crawl_results").removeClass("hidden");
        $("#crw_refresh_btn").removeClass("hidden");
        $("#crw_nxt_prv_btn").removeClass("hidden");
        show_crawler(res);
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        if (errorThrown == "UNAUTHORIZED") {
          $("#login_first").removeClass("hidden");
          $("#crawl_results").addClass("hidden");
          $("#crw_refresh_btn").addClass("hidden");
          $("#crw_nxt_prv_btn").addClass("hidden");
          $("#home").addClass("hidden");
          $("#crawler_area").addClass("hidden");
          $("#compare_area").addClass("hidden");
        } else {
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
