<script>
    length = document.getElementById("json_length").innerText;
    document.getElementById("json_length").innerText = "";
    renderjson.set_icons('▶','▼')
    renderjson.set_collapse_msg(function (asd) {return "...";});
    for (let i=1; i<=length; i++) {
        value = document.getElementById("json_event_"+i).innerText;
        document.getElementById("json_event_"+i).innerText = "";
        document.getElementById("json_event_"+i).appendChild(renderjson(JSON.parse(value)));
    }
</script>