<script>
    length = document.getElementById("json_length").innerText;
    document.getElementById("json_length").innerText = "";
    renderjson.set_icons('▶','▼')
    renderjson.set_collapse_msg(function (asd) {return "...";});
    arr = [];
    for (let i=1; i<=length; i++) {
        value = document.getElementById("json_event_"+i).innerText;
        arr.push(value);
        document.getElementById("json_event_"+i).innerText = "";
        document.getElementById("json_clipboard_"+i).addEventListener("click", function() { navigator.clipboard.writeText(arr[i-1]); });
        document.getElementById("json_event_"+i).appendChild(renderjson(JSON.parse(value)));
    }
</script>