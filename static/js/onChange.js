function onChange()
{
    var range_bar = document.getElementById("range-bar");
    var range_bar_value = document.getElementById("range-bar-value");
    var text = document.getElementById("verses");
    var range_bar_meta = document.getElementById("range-bar-meta");

    range_bar_value.innerHTML = range_bar.value;      
    range_bar_meta.value = range_bar.value;
    text.style["font-size"] = `${range_bar.value}px`;
}