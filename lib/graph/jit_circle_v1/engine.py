#!/usr/bin/env python
# -*- coding: utf-8 -*-
import string
import random
import json
from core.alert import messages
from core.compatible import version


def start(graph_flag, language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION):
    """
    generate the jit_circle_v1_graph with events

    Args:
        graph_flag: graph name
        language: language
        data: events in JSON
        _HOST: host key
        _USERNAME: username key
        _PASSWORD: password key
        _PORT: port key
        _TYPE: module name key
        _DESCRIPTION: description key

    Returns:
        a graph in HTML
    """
    # define  a normalised_json
    normalisedjson = {
        "name": "Started attack",
        "children": {}
    }
    # get data for normalised_json
    for each_scan in data:

        if each_scan['HOST'] not in normalisedjson['children']:
            normalisedjson['children'].update({each_scan['HOST']: {}})
            normalisedjson['children'][each_scan['HOST']].update(
                {each_scan['TYPE']: []})

        if each_scan['TYPE'] not in normalisedjson['children'][each_scan['HOST']]:
            normalisedjson['children'][each_scan['HOST']].update(
                {each_scan['TYPE']: []})

        normalisedjson['children'][each_scan['HOST']][each_scan['TYPE']].append("HOST: \"%s\", PORT:\"%s\", DESCRIPTION:\"%s\", USERNAME:\"%s\", PASSWORD:\"%s\"" % (
            each_scan['HOST'], each_scan['PORT'], each_scan['DESCRIPTION'], each_scan['USERNAME'], each_scan['PASSWORD']))

    # define a dgraph_json
    dgraph = {
        "id": "0",
        "data": [],
        "relation": "",
        "name": "Start Attacking",
        "children": []
    }

    # get data for dgraph_json
    n = 1
    for host in normalisedjson['children']:

        dgraph['children'].append({"id": str(n), "name": host, "data": {"relation": "Start Attacking"}, "children": [{"id": ''.join(random.choice(
            string.ascii_letters + string.digits) for _ in range(20)), "name": otype, "data": {"band": [description.split(', ')[2].lstrip("DESCRIPTION: ").strip("\"") for description in normalisedjson['children'][host][otype]][0], "relation": [description.split(', ')[1:] for description in normalisedjson['children'][host][otype]]}, "children": [{"children": [], "data":{"band": description.split(', ')[2], "relation": description.split(', ')[1:]}, "id": ''.join(random.choice(
                string.ascii_letters + string.digits) for _ in range(20)), "name": description.split(', ')[1].lstrip("PORT: ").strip("\"")} for description in normalisedjson['children'][host][otype]]} for otype in normalisedjson['children'][host]]})
        n += 1

    data = '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<!-- THIS SAMPLE COPIED AND MODIFIED FROM http://philogb.github.io/jit/static/v20/Jit/Examples/Hypertree/example1.html -->
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>__html_title_to_replace__</title>

<!-- CSS Files -->
<!-- MODIFIED FROM http://philogb.github.io/jit/static/v20/Jit/Examples/css/base.css
\t\t\t\t   http://philogb.github.io/jit/static/v20/Jit/Examples/css/Hypertree.css -->
<style>
html, body {
    margina:0;
    padding:0;
    font-family: "Lucida Grande", Verdana;
    font-size: 0.9em;
    text-align: center;
    background-color:#F2F2F2;
}

input, select {
    font-size:0.9em;
}

table {
    margin-top:-10px;
    margin-left:7px;
}

h4 {
    font-size:1.1em;
    text-decoration:none;
    font-weight:normal;
    color:#23A4FF;
}

a {
    color:#23A4FF;
}

#container {
    width: 1000px;
    height: 600px;
    margin:0 auto;
    position:relative;
}

#left-container,
#right-container,
#center-container {
    height:600px;
    position:absolute;
    top:0;
}

#left-container, #right-container {
    width:200px;
    color:#686c70;
    text-align: left;
    overflow: auto;
    background-color:#fff;
    background-repeat:no-repeat;
    border-bottom:1px solid #ddd;
}

#left-container {
    left:0;
    background-image:url(\'col2.png\');
    background-position:center right;
    border-left:1px solid #ddd;

}

#right-container {
    right:0;
    background-image:url(\'col1.png\');
    background-position:center left;
    border-right:1px solid #ddd;
}

#right-container h4{
    text-indent:8px;
}

#center-container {
    width:600px;
    left:200px;
    background-color:#1a1a1a;
    color:#ccc;
}

.text {
    margin: 7px;
}

#inner-details {
    font-size:0.8em;
    list-style:none;
    margin:7px;
}

#log {
    position:absolute;
    top:10px;
    font-size:1.0em;
    font-weight:bold;
    color:#23A4FF;
}


#infovis {
    position:relative;
    width:600px;
    height:600px;
    margin:auto;
    overflow:hidden;
}

/*TOOLTIPS*/
.tip {
    color: #111;
    width: 139px;
    background-color: white;
    border:1px solid #ccc;
    -moz-box-shadow:#555 2px 2px 8px;
    -webkit-box-shadow:#555 2px 2px 8px;
    -o-box-shadow:#555 2px 2px 8px;
    box-shadow:#555 2px 2px 8px;
    opacity:0.9;
    filter:alpha(opacity=90);
    font-size:10px;
    font-family:Verdana, Geneva, Arial, Helvetica, sans-serif;
    padding:7px;
}

#infovis-canvaswidget {
  margin:25px 0 0 25px;
}

</style>
<a target="_blank" href="https://github.com/zdresearch/OWASP-Nettacker"><h2>OWASP Nettacker</h2></a>
<!--[if IE]><script language="javascript" type="text/javascript" src="../../Extras/excanvas.js"></script><![endif]-->

<!-- JIT Library File -->
<script>
__js_jit_lib_will_locate_here__
</script>
<!-- jit library -->
<script>
/*
Copyright (c) 2011 Sencha Inc. - Author: Nicolas Garcia Belmonte (http://philogb.github.com/)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

 */

(function() {
  /**
   * @param {Object} w
   * @return {undefined}
   */
  window.$jit = function(w) {
    w = w || window;
    var k;
    for (k in $jit) {
      if ($jit[k].$extend) {
        w[k] = $jit[k];
      }
    }
  };
  /** @type {string} */
  $jit.version = "2.0.1";
  /**
   * @param {?} obj
   * @return {?}
   */
  var $ = function(obj) {
    return document.getElementById(obj);
  };
  /**
   * @return {undefined}
   */
  $.empty = function() {
  };
  /**
   * @param {?} obj
   * @param {?} opt_attributes
   * @return {?}
   */
  $.extend = function(obj, opt_attributes) {
    var val;
    for (val in opt_attributes || {}) {
      obj[val] = opt_attributes[val];
    }
    return obj;
  };
  /**
   * @param {boolean} recurring
   * @return {?}
   */
  $.lambda = function(recurring) {
    return typeof recurring == "function" ? recurring : function() {
      return recurring;
    };
  };
  /** @type {function (): number} */
  $.time = Date.now || function() {
    return+new Date;
  };
  /**
   * @param {string} obj
   * @return {?}
   */
  $.splat = function(obj) {
    var type = $.type(obj);
    return type ? type != "array" ? [obj] : obj : [];
  };
  /**
   * @param {Object} obj
   * @return {?}
   */
  $.type = function(obj) {
    /** @type {string} */
    var t = $.type.s.call(obj).match(/^\\[object\\s(.*)\\]$/)[1].toLowerCase();
    if (t != "object") {
      return t;
    }
    if (obj && obj.$$family) {
      return obj.$$family;
    }
    return obj && (obj.nodeName && obj.nodeType == 1) ? "element" : t;
  };
  /** @type {function (this:*): string} */
  $.type.s = Object.prototype.toString;
  /**
   * @param {?} opt_attributes
   * @param {Function} f
   * @return {undefined}
   */
  $.each = function(opt_attributes, f) {
    var value = $.type(opt_attributes);
    if (value == "object") {
      var i;
      for (i in opt_attributes) {
        f(opt_attributes[i], i);
      }
    } else {
      /** @type {number} */
      var m = 0;
      var n = opt_attributes.length;
      for (;m < n;m++) {
        f(opt_attributes[m], m);
      }
    }
  };
  /**
   * @param {Array} arr
   * @param {?} obj
   * @return {?}
   */
  $.indexOf = function(arr, obj) {
    if (Array.indexOf) {
      return arr.indexOf(obj);
    }
    /** @type {number} */
    var i = 0;
    var e = arr.length;
    for (;i < e;i++) {
      if (arr[i] === obj) {
        return i;
      }
    }
    return-1;
  };
  /**
   * @param {?} attributes
   * @param {Function} fun
   * @return {?}
   */
  $.map = function(attributes, fun) {
    /** @type {Array} */
    var fin = [];
    $.each(attributes, function(k, v) {
      fin.push(fun(k, v));
    });
    return fin;
  };
  /**
   * @param {?} arr
   * @param {Function} callback
   * @param {number} mayParseLabeledStatementInstead
   * @return {?}
   */
  $.reduce = function(arr, callback, mayParseLabeledStatementInstead) {
    var j = arr.length;
    if (j == 0) {
      return mayParseLabeledStatementInstead;
    }
    var basis = arguments.length == 3 ? mayParseLabeledStatementInstead : arr[--j];
    for (;j--;) {
      basis = callback(basis, arr[j]);
    }
    return basis;
  };
  /**
   * @return {?}
   */
  $.merge = function() {
    var mix = {};
    /** @type {number} */
    var argsIndex = 0;
    /** @type {number} */
    var argsLength = arguments.length;
    for (;argsIndex < argsLength;argsIndex++) {
      var iterable = arguments[argsIndex];
      if ($.type(iterable) != "object") {
        continue;
      }
      var key;
      for (key in iterable) {
        var op = iterable[key];
        var mp = mix[key];
        mix[key] = mp && ($.type(op) == "object" && $.type(mp) == "object") ? $.merge(mp, op) : $.unlink(op);
      }
    }
    return mix;
  };
  /**
   * @param {Object} object
   * @return {?}
   */
  $.unlink = function(object) {
    var safe;
    switch($.type(object)) {
      case "object":
        safe = {};
        var key;
        for (key in object) {
          safe[key] = $.unlink(object[key]);
        }
        break;
      case "array":
        /** @type {Array} */
        safe = [];
        /** @type {number} */
        var i = 0;
        var length = object.length;
        for (;i < length;i++) {
          safe[i] = $.unlink(object[i]);
        }
        break;
      default:
        return object;
    }
    return safe;
  };
  /**
   * @return {?}
   */
  $.zip = function() {
    if (arguments.length === 0) {
      return[];
    }
    /** @type {number} */
    var j = 0;
    /** @type {Array} */
    var out = [];
    /** @type {number} */
    var argLength = arguments.length;
    var jl = arguments[0].length;
    for (;j < jl;j++) {
      /** @type {number} */
      var i = 0;
      /** @type {Array} */
      var copies = [];
      for (;i < argLength;i++) {
        copies.push(arguments[i][j]);
      }
      out.push(copies);
    }
    return out;
  };
  /**
   * @param {Array} ans
   * @param {boolean} array
   * @return {?}
   */
  $.rgbToHex = function(ans, array) {
    if (ans.length < 3) {
      return null;
    }
    if (ans.length == 4 && (ans[3] == 0 && !array)) {
      return "transparent";
    }
    /** @type {Array} */
    var hex = [];
    /** @type {number} */
    var i = 0;
    for (;i < 3;i++) {
      /** @type {string} */
      var bit = (ans[i] - 0).toString(16);
      hex.push(bit.length == 1 ? "0" + bit : bit);
    }
    return array ? hex : "#" + hex.join("");
  };
  /**
   * @param {string} hex
   * @return {?}
   */
  $.hexToRgb = function(hex) {
    if (hex.length != 7) {
      hex = hex.match(/^#?(\\w{1,2})(\\w{1,2})(\\w{1,2})$/);
      hex.shift();
      if (hex.length != 3) {
        return null;
      }
      /** @type {Array} */
      var rgb = [];
      /** @type {number} */
      var index = 0;
      for (;index < 3;index++) {
        var value = hex[index];
        if (value.length == 1) {
          value += value;
        }
        rgb.push(parseInt(value, 16));
      }
      return rgb;
    } else {
      /** @type {number} */
      hex = parseInt(hex.slice(1), 16);
      return[hex >> 16, hex >> 8 & 255, hex & 255];
    }
  };
  /**
   * @param {Element} elem
   * @return {undefined}
   */
  $.destroy = function(elem) {
    $.clean(elem);
    if (elem.parentNode) {
      elem.parentNode.removeChild(elem);
    }
    if (elem.clearAttributes) {
      elem.clearAttributes();
    }
  };
  /**
   * @param {Element} el
   * @return {undefined}
   */
  $.clean = function(el) {
    var nodes = el.childNodes;
    /** @type {number} */
    var i = 0;
    var len = nodes.length;
    for (;i < len;i++) {
      $.destroy(nodes[i]);
    }
  };
  /**
   * @param {Object} elem
   * @param {string} type
   * @param {Function} cb
   * @return {undefined}
   */
  $.addEvent = function(elem, type, cb) {
    if (elem.addEventListener) {
      elem.addEventListener(type, cb, false);
    } else {
      elem.attachEvent("on" + type, cb);
    }
  };
  /**
   * @param {Object} element
   * @param {Object} events
   * @return {undefined}
   */
  $.addEvents = function(element, events) {
    var type;
    for (type in events) {
      $.addEvent(element, type, events[type]);
    }
  };
  /**
   * @param {Element} domElement
   * @param {string} selector
   * @return {?}
   */
  $.hasClass = function(domElement, selector) {
    return(" " + domElement.className + " ").indexOf(" " + selector + " ") > -1;
  };
  /**
   * @param {Element} domElement
   * @param {string} className
   * @return {undefined}
   */
  $.addClass = function(domElement, className) {
    if (!$.hasClass(domElement, className)) {
      /** @type {string} */
      domElement.className = domElement.className + " " + className;
    }
  };
  /**
   * @param {Element} element
   * @param {string} classNames
   * @return {undefined}
   */
  $.removeClass = function(element, classNames) {
    element.className = element.className.replace(new RegExp("(^|\\\\s)" + classNames + "(?:\\\\s|$)"), "$1");
  };
  /**
   * @param {Object} c
   * @return {?}
   */
  $.getPos = function(c) {
    /**
     * @param {Object} elem
     * @return {?}
     */
    function getOffsets(elem) {
      var offset = {
        x : 0,
        y : 0
      };
      for (;elem && !isBody(elem);) {
        offset.x += elem.offsetLeft;
        offset.y += elem.offsetTop;
        elem = elem.offsetParent;
      }
      return offset;
    }
    /**
     * @param {HTMLElement} element
     * @return {?}
     */
    function getScrolls(element) {
      var position = {
        x : 0,
        y : 0
      };
      for (;element && !isBody(element);) {
        position.x += element.scrollLeft;
        position.y += element.scrollTop;
        element = element.parentNode;
      }
      return position;
    }
    /**
     * @param {Object} element
     * @return {?}
     */
    function isBody(element) {
      return/^(?:body|html)$/i.test(element.tagName);
    }
    var pos = getOffsets(c);
    var e = getScrolls(c);
    return{
      x : pos.x - e.x,
      y : pos.y - e.y
    };
  };
  $.event = {
    /**
     * @param {Object} adj
     * @param {Object} lab
     * @return {?}
     */
    get : function(adj, lab) {
      lab = lab || window;
      return adj || lab.event;
    },
    /**
     * @param {Event} e
     * @return {?}
     */
    getWheel : function(e) {
      return e.wheelDelta ? e.wheelDelta / 120 : -(e.detail || 0) / 3;
    },
    /**
     * @param {Event} event
     * @return {?}
     */
    isRightClick : function(event) {
      return event.which == 3 || event.button == 2;
    },
    /**
     * @param {Object} value
     * @param {Object} win
     * @return {?}
     */
    getPos : function(value, win) {
      win = win || window;
      value = value || win.event;
      var doc = win.document;
      doc = doc.documentElement || doc.body;
      if (value.touches && value.touches.length) {
        value = value.touches[0];
      }
      var pos = {
        x : value.pageX || value.clientX + doc.scrollLeft,
        y : value.pageY || value.clientY + doc.scrollTop
      };
      return pos;
    },
    /**
     * @param {Event} event
     * @return {undefined}
     */
    stop : function(event) {
      if (event.stopPropagation) {
        event.stopPropagation();
      }
      /** @type {boolean} */
      event.cancelBubble = true;
      if (event.preventDefault) {
        event.preventDefault();
      } else {
        /** @type {boolean} */
        event.returnValue = false;
      }
    }
  };
  /** @type {function (?): ?} */
  $jit.util = $jit.id = $;
  /**
   * @param {Object} properties
   * @return {?}
   */
  var Class = function(properties) {
    properties = properties || {};
    /**
     * @return {?}
     */
    var klass = function() {
      var p;
      for (p in this) {
        if (typeof this[p] != "function") {
          this[p] = $.unlink(this[p]);
        }
      }
      /** @type {function (): ?} */
      this.constructor = klass;
      if (Class.prototyping) {
        return this;
      }
      var instance = this.initialize ? this.initialize.apply(this, arguments) : this;
      /** @type {string} */
      this.$$family = "class";
      return instance;
    };
    var mutator;
    for (mutator in Class.Mutators) {
      if (!properties[mutator]) {
        continue;
      }
      properties = Class.Mutators[mutator](properties, properties[mutator]);
      delete properties[mutator];
    }
    $.extend(klass, this);
    /** @type {function (Object): ?} */
    klass.constructor = Class;
    /** @type {Object} */
    klass.prototype = properties;
    return klass;
  };
  Class.Mutators = {
    /**
     * @param {Object} self
     * @param {string} klasses
     * @return {?}
     */
    Implements : function(self, klasses) {
      $.each($.splat(klasses), function(klass) {
        /** @type {string} */
        Class.prototyping = klass;
        var iterable = typeof klass == "function" ? new klass : klass;
        var key;
        for (key in iterable) {
          if (!(key in self)) {
            self[key] = iterable[key];
          }
        }
        delete Class.prototyping;
      });
      return self;
    }
  };
  $.extend(Class, {
    /**
     * @param {Object} object
     * @param {Object} properties
     * @return {?}
     */
    inherit : function(object, properties) {
      var key;
      for (key in properties) {
        var override = properties[key];
        var previous = object[key];
        var type = $.type(override);
        if (previous && type == "function") {
          if (override != previous) {
            Class.override(object, key, override);
          }
        } else {
          if (type == "object") {
            object[key] = $.merge(previous, override);
          } else {
            object[key] = override;
          }
        }
      }
      return object;
    },
    /**
     * @param {Object} object
     * @param {string} name
     * @param {Function} matcherFunction
     * @return {undefined}
     */
    override : function(object, name, matcherFunction) {
      var parent = Class.prototyping;
      if (parent && object[name] != parent[name]) {
        /** @type {null} */
        parent = null;
      }
      /**
       * @return {?}
       */
      var next = function() {
        var tmp = this.parent;
        this.parent = parent ? parent[name] : object[name];
        var rv = matcherFunction.apply(this, arguments);
        this.parent = tmp;
        return rv;
      };
      /** @type {function (): ?} */
      object[name] = next;
    }
  });
  /**
   * @return {?}
   */
  Class.prototype.implement = function() {
    var proto = this.prototype;
    $.each(Array.prototype.slice.call(arguments || []), function(properties) {
      Class.inherit(proto, properties);
    });
    return this;
  };
  /** @type {function (Object): ?} */
  $jit.Class = Class;
  $jit.json = {
    /**
     * @param {?} attributes
     * @param {?} maxLevel
     * @return {undefined}
     */
    prune : function(attributes, maxLevel) {
      this.each(attributes, function(elem, i) {
        if (i == maxLevel && elem.children) {
          delete elem.children;
          /** @type {Array} */
          elem.children = [];
        }
      });
    },
    /**
     * @param {Object} tree
     * @param {?} id
     * @return {?}
     */
    getParent : function(tree, id) {
      if (tree.id == id) {
        return false;
      }
      var ch = tree.children;
      if (ch && ch.length > 0) {
        /** @type {number} */
        var i = 0;
        for (;i < ch.length;i++) {
          if (ch[i].id == id) {
            return tree;
          } else {
            var ans = this.getParent(ch[i], id);
            if (ans) {
              return ans;
            }
          }
        }
      }
      return false;
    },
    /**
     * @param {Object} tree
     * @param {?} id
     * @return {?}
     */
    getSubtree : function(tree, id) {
      if (tree.id == id) {
        return tree;
      }
      /** @type {number} */
      var i = 0;
      var ch = tree.children;
      for (;ch && i < ch.length;i++) {
        var t = this.getSubtree(ch[i], id);
        if (t != null) {
          return t;
        }
      }
      return null;
    },
    /**
     * @param {number} value
     * @param {number} opt_isDefault
     * @param {Function} recurring
     * @param {Function} action
     * @return {undefined}
     */
    eachLevel : function(value, opt_isDefault, recurring, action) {
      if (opt_isDefault <= recurring) {
        action(value, opt_isDefault);
        if (!value.children) {
          return;
        }
        /** @type {number} */
        var i = 0;
        var codeSegments = value.children;
        for (;i < codeSegments.length;i++) {
          this.eachLevel(codeSegments[i], opt_isDefault + 1, recurring, action);
        }
      }
    },
    /**
     * @param {?} opt_attributes
     * @param {Function} action
     * @return {undefined}
     */
    each : function(opt_attributes, action) {
      this.eachLevel(opt_attributes, 0, Number.MAX_VALUE, action);
    }
  };
  $jit.Trans = {
    $extend : true,
    /**
     * @param {?} t
     * @return {?}
     */
    linear : function(t) {
      return t;
    }
  };
  var $cookies = $jit.Trans;
  (function() {
    /**
     * @param {Function} transition
     * @param {Text} params
     * @return {?}
     */
    var makeTrans = function(transition, params) {
      params = $.splat(params);
      return $.extend(transition, {
        /**
         * @param {?} pos
         * @return {?}
         */
        easeIn : function(pos) {
          return transition(pos, params);
        },
        /**
         * @param {number} pos
         * @return {?}
         */
        easeOut : function(pos) {
          return 1 - transition(1 - pos, params);
        },
        /**
         * @param {number} pos
         * @return {?}
         */
        easeInOut : function(pos) {
          return pos <= 0.5 ? transition(2 * pos, params) / 2 : (2 - transition(2 * (1 - pos), params)) / 2;
        }
      });
    };
    var transitions = {
      /**
       * @param {?} p
       * @param {Array} x
       * @return {?}
       */
      Pow : function(p, x) {
        return Math.pow(p, x[0] || 6);
      },
      /**
       * @param {number} p
       * @return {?}
       */
      Expo : function(p) {
        return Math.pow(2, 8 * (p - 1));
      },
      /**
       * @param {?} p
       * @return {?}
       */
      Circ : function(p) {
        return 1 - Math.sin(Math.acos(p));
      },
      /**
       * @param {number} p
       * @return {?}
       */
      Sine : function(p) {
        return 1 - Math.sin((1 - p) * Math.PI / 2);
      },
      /**
       * @param {?} p
       * @param {number} x
       * @return {?}
       */
      Back : function(p, x) {
        x = x[0] || 1.618;
        return Math.pow(p, 2) * ((x + 1) * p - x);
      },
      /**
       * @param {number} p
       * @return {?}
       */
      Bounce : function(p) {
        var value;
        /** @type {number} */
        var a = 0;
        /** @type {number} */
        var b = 1;
        for (;1;a += b, b /= 2) {
          if (p >= (7 - 4 * a) / 11) {
            /** @type {number} */
            value = b * b - Math.pow((11 - 6 * a - 11 * p) / 4, 2);
            break;
          }
        }
        return value;
      },
      /**
       * @param {number} p
       * @param {Array} x
       * @return {?}
       */
      Elastic : function(p, x) {
        return Math.pow(2, 10 * --p) * Math.cos(20 * p * Math.PI * (x[0] || 1) / 3);
      }
    };
    $.each(transitions, function(value, key) {
      $cookies[key] = makeTrans(value);
    });
    $.each(["Quad", "Cubic", "Quart", "Quint"], function(key, dataAndEvents) {
      $cookies[key] = makeTrans(function(pos) {
        return Math.pow(pos, [dataAndEvents + 2]);
      });
    });
  })();
  var Animation = new Class({
    /**
     * @param {Object} options
     * @return {undefined}
     */
    initialize : function(options) {
      this.setOptions(options);
    },
    /**
     * @param {Object} options
     * @return {?}
     */
    setOptions : function(options) {
      var opt = {
        duration : 2500,
        fps : 40,
        transition : $cookies.Quart.easeInOut,
        /** @type {function (): undefined} */
        compute : $.empty,
        /** @type {function (): undefined} */
        complete : $.empty,
        link : "ignore"
      };
      this.opt = $.merge(opt, options || {});
      return this;
    },
    /**
     * @return {undefined}
     */
    step : function() {
      /** @type {number} */
      var time = $.time();
      var opt = this.opt;
      if (time < this.time + opt.duration) {
        var from = opt.transition((time - this.time) / opt.duration);
        opt.compute(from);
      } else {
        this.timer = clearInterval(this.timer);
        opt.compute(1);
        opt.complete();
      }
    },
    /**
     * @return {?}
     */
    start : function() {
      if (!this.check()) {
        return this;
      }
      /** @type {number} */
      this.time = 0;
      this.startTimer();
      return this;
    },
    /**
     * @return {?}
     */
    startTimer : function() {
      var self = this;
      var fps = this.opt.fps;
      if (this.timer) {
        return false;
      }
      /** @type {number} */
      this.time = $.time() - this.time;
      /** @type {number} */
      this.timer = setInterval(function() {
        self.step();
      }, Math.round(1E3 / fps));
      return true;
    },
    /**
     * @return {?}
     */
    pause : function() {
      this.stopTimer();
      return this;
    },
    /**
     * @return {?}
     */
    resume : function() {
      this.startTimer();
      return this;
    },
    /**
     * @return {?}
     */
    stopTimer : function() {
      if (!this.timer) {
        return false;
      }
      /** @type {number} */
      this.time = $.time() - this.time;
      this.timer = clearInterval(this.timer);
      return true;
    },
    /**
     * @return {?}
     */
    check : function() {
      if (!this.timer) {
        return true;
      }
      if (this.opt.link == "cancel") {
        this.stopTimer();
        return true;
      }
      return false;
    }
  });
  /**
   * @return {?}
   */
  var Options = function() {
    /** @type {Arguments} */
    var args = arguments;
    /** @type {number} */
    var i = 0;
    /** @type {number} */
    var argLength = args.length;
    var methods = {};
    for (;i < argLength;i++) {
      var attributes = Options[args[i]];
      if (attributes.$extend) {
        $.extend(methods, attributes);
      } else {
        methods[args[i]] = attributes;
      }
    }
    return methods;
  };
  Options.AreaChart = {
    $extend : true,
    animate : true,
    labelOffset : 3,
    type : "stacked",
    Tips : {
      enable : false,
      /** @type {function (): undefined} */
      onShow : $.empty,
      /** @type {function (): undefined} */
      onHide : $.empty
    },
    Events : {
      enable : false,
      /** @type {function (): undefined} */
      onClick : $.empty
    },
    selectOnHover : true,
    showAggregates : true,
    showLabels : true,
    filterOnClick : false,
    restoreOnRightClick : false
  };
  Options.Margin = {
    $extend : false,
    top : 0,
    left : 0,
    right : 0,
    bottom : 0
  };
  Options.Canvas = {
    $extend : true,
    injectInto : "id",
    type : "2D",
    width : false,
    height : false,
    useCanvas : false,
    withLabels : true,
    background : false,
    Scene : {
      Lighting : {
        enable : false,
        ambient : [1, 1, 1],
        directional : {
          direction : {
            x : -100,
            y : -100,
            z : -100
          },
          color : [0.5, 0.3, 0.1]
        }
      }
    }
  };
  Options.Tree = {
    $extend : true,
    orientation : "left",
    subtreeOffset : 8,
    siblingOffset : 5,
    indent : 10,
    multitree : false,
    align : "center"
  };
  Options.Node = {
    $extend : false,
    overridable : false,
    type : "circle",
    color : "#ccb",
    alpha : 1,
    dim : 3,
    height : 20,
    width : 90,
    autoHeight : false,
    autoWidth : false,
    lineWidth : 1,
    transform : true,
    align : "center",
    angularWidth : 1,
    span : 1,
    CanvasStyles : {}
  };
  Options.Edge = {
    $extend : false,
    overridable : false,
    type : "line",
    color : "#ccb",
    lineWidth : 1,
    dim : 15,
    alpha : 1,
    epsilon : 7,
    CanvasStyles : {}
  };
  Options.Fx = {
    $extend : true,
    fps : 40,
    duration : 2500,
    transition : $jit.Trans.Quart.easeInOut,
    clearCanvas : true
  };
  Options.Label = {
    $extend : false,
    overridable : false,
    type : "HTML",
    style : " ",
    size : 10,
    family : "sans-serif",
    textAlign : "center",
    textBaseline : "alphabetic",
    color : "#fff"
  };
  Options.Tips = {
    $extend : false,
    enable : false,
    type : "auto",
    offsetX : 20,
    offsetY : 20,
    force : false,
    /** @type {function (): undefined} */
    onShow : $.empty,
    /** @type {function (): undefined} */
    onHide : $.empty
  };
  Options.NodeStyles = {
    $extend : false,
    enable : false,
    type : "auto",
    stylesHover : false,
    stylesClick : false
  };
  Options.Events = {
    $extend : false,
    enable : false,
    enableForEdges : false,
    type : "auto",
    /** @type {function (): undefined} */
    onClick : $.empty,
    /** @type {function (): undefined} */
    onRightClick : $.empty,
    /** @type {function (): undefined} */
    onMouseMove : $.empty,
    /** @type {function (): undefined} */
    onMouseEnter : $.empty,
    /** @type {function (): undefined} */
    onMouseLeave : $.empty,
    /** @type {function (): undefined} */
    onDragStart : $.empty,
    /** @type {function (): undefined} */
    onDragMove : $.empty,
    /** @type {function (): undefined} */
    onDragCancel : $.empty,
    /** @type {function (): undefined} */
    onDragEnd : $.empty,
    /** @type {function (): undefined} */
    onTouchStart : $.empty,
    /** @type {function (): undefined} */
    onTouchMove : $.empty,
    /** @type {function (): undefined} */
    onTouchEnd : $.empty,
    /** @type {function (): undefined} */
    onMouseWheel : $.empty
  };
  Options.Navigation = {
    $extend : false,
    enable : false,
    type : "auto",
    panning : false,
    zooming : false
  };
  Options.Controller = {
    $extend : true,
    /** @type {function (): undefined} */
    onBeforeCompute : $.empty,
    /** @type {function (): undefined} */
    onAfterCompute : $.empty,
    /** @type {function (): undefined} */
    onCreateLabel : $.empty,
    /** @type {function (): undefined} */
    onPlaceLabel : $.empty,
    /** @type {function (): undefined} */
    onComplete : $.empty,
    /** @type {function (): undefined} */
    onBeforePlotLine : $.empty,
    /** @type {function (): undefined} */
    onAfterPlotLine : $.empty,
    /** @type {function (): undefined} */
    onBeforePlotNode : $.empty,
    /** @type {function (): undefined} */
    onAfterPlotNode : $.empty,
    request : false
  };
  var Events = {
    /**
     * @param {?} className
     * @param {Object} viz
     * @return {undefined}
     */
    initialize : function(className, viz) {
      /** @type {Object} */
      this.viz = viz;
      this.canvas = viz.canvas;
      this.config = viz.config[className];
      this.nodeTypes = viz.fx.nodeTypes;
      var type = this.config.type;
      /** @type {boolean} */
      this.dom = type == "auto" ? viz.config.Label.type != "Native" : type != "Native";
      this.labelContainer = this.dom && viz.labels.getLabelContainer();
      if (this.isEnabled()) {
        this.initializePost();
      }
    },
    /** @type {function (): undefined} */
    initializePost : $.empty,
    setAsProperty : $.lambda(false),
    /**
     * @return {?}
     */
    isEnabled : function() {
      return this.config.enable;
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {boolean} recurring
     * @return {?}
     */
    isLabel : function(adj, lab, recurring) {
      adj = $.event.get(adj, lab);
      var labelContainer = this.labelContainer;
      var target = adj.target || adj.srcElement;
      var related = adj.relatedTarget;
      if (recurring) {
        return related && (related == this.viz.canvas.getCtx().canvas && (!!target && this.isDescendantOf(target, labelContainer)));
      } else {
        return this.isDescendantOf(target, labelContainer);
      }
    },
    /**
     * @param {HTMLElement} elem
     * @param {?} par
     * @return {?}
     */
    isDescendantOf : function(elem, par) {
      for (;elem && elem.parentNode;) {
        if (elem.parentNode == par) {
          return elem;
        }
        elem = elem.parentNode;
      }
      return false;
    }
  };
  var Aspect = {
    /** @type {function (): undefined} */
    onMouseUp : $.empty,
    /** @type {function (): undefined} */
    onMouseDown : $.empty,
    /** @type {function (): undefined} */
    onMouseMove : $.empty,
    /** @type {function (): undefined} */
    onMouseOver : $.empty,
    /** @type {function (): undefined} */
    onMouseOut : $.empty,
    /** @type {function (): undefined} */
    onMouseWheel : $.empty,
    /** @type {function (): undefined} */
    onTouchStart : $.empty,
    /** @type {function (): undefined} */
    onTouchMove : $.empty,
    /** @type {function (): undefined} */
    onTouchEnd : $.empty,
    /** @type {function (): undefined} */
    onTouchCancel : $.empty
  };
  var Tips = new Class({
    /**
     * @param {?} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.viz = viz;
      this.canvas = viz.canvas;
      /** @type {boolean} */
      this.node = false;
      /** @type {boolean} */
      this.edge = false;
      /** @type {Array} */
      this.registeredObjects = [];
      this.attachEvents();
    },
    /**
     * @return {undefined}
     */
    attachEvents : function() {
      var element = this.canvas.getElement();
      var that = this;
      element.oncontextmenu = $.lambda(false);
      $.addEvents(element, {
        /**
         * @param {Object} e
         * @param {Object} win
         * @return {undefined}
         */
        mouseup : function(e, win) {
          var event = $.event.get(e, win);
          that.handleEvent("MouseUp", e, win, that.makeEventObject(e, win), $.event.isRightClick(event));
        },
        /**
         * @param {Object} e
         * @param {Object} win
         * @return {undefined}
         */
        mousedown : function(e, win) {
          var event = $.event.get(e, win);
          that.handleEvent("MouseDown", e, win, that.makeEventObject(e, win), $.event.isRightClick(event));
        },
        /**
         * @param {Object} e
         * @param {?} win
         * @return {undefined}
         */
        mousemove : function(e, win) {
          that.handleEvent("MouseMove", e, win, that.makeEventObject(e, win));
        },
        /**
         * @param {Object} e
         * @param {?} win
         * @return {undefined}
         */
        mouseover : function(e, win) {
          that.handleEvent("MouseOver", e, win, that.makeEventObject(e, win));
        },
        /**
         * @param {Object} e
         * @param {?} win
         * @return {undefined}
         */
        mouseout : function(e, win) {
          that.handleEvent("MouseOut", e, win, that.makeEventObject(e, win));
        },
        /**
         * @param {Object} e
         * @param {?} win
         * @return {undefined}
         */
        touchstart : function(e, win) {
          that.handleEvent("TouchStart", e, win, that.makeEventObject(e, win));
        },
        /**
         * @param {Object} e
         * @param {?} win
         * @return {undefined}
         */
        touchmove : function(e, win) {
          that.handleEvent("TouchMove", e, win, that.makeEventObject(e, win));
        },
        /**
         * @param {Object} e
         * @param {?} win
         * @return {undefined}
         */
        touchend : function(e, win) {
          that.handleEvent("TouchEnd", e, win, that.makeEventObject(e, win));
        }
      });
      /**
       * @param {Object} from
       * @param {Object} win
       * @return {undefined}
       */
      var handleMouseWheel = function(from, win) {
        var event = $.event.get(from, win);
        var wheel = $.event.getWheel(event);
        that.handleEvent("MouseWheel", from, win, wheel);
      };
      if (!document.getBoxObjectFor && window.mozInnerScreenX == null) {
        $.addEvent(element, "mousewheel", handleMouseWheel);
      } else {
        element.addEventListener("DOMMouseScroll", handleMouseWheel, false);
      }
    },
    /**
     * @param {?} obj
     * @return {undefined}
     */
    register : function(obj) {
      this.registeredObjects.push(obj);
    },
    /**
     * @return {undefined}
     */
    handleEvent : function() {
      /** @type {Array.<?>} */
      var args = Array.prototype.slice.call(arguments);
      var type = args.shift();
      /** @type {number} */
      var i = 0;
      var regs = this.registeredObjects;
      var l = regs.length;
      for (;i < l;i++) {
        regs[i]["on" + type].apply(regs[i], args);
      }
    },
    /**
     * @param {Object} prop
     * @param {?} win
     * @return {?}
     */
    makeEventObject : function(prop, win) {
      var that = this;
      var graph = this.viz.graph;
      var fx = this.viz.fx;
      var ntypes = fx.nodeTypes;
      var etypes = fx.edgeTypes;
      return{
        pos : false,
        node : false,
        edge : false,
        contains : false,
        getNodeCalled : false,
        getEdgeCalled : false,
        /**
         * @return {?}
         */
        getPos : function() {
          var canvas = that.viz.canvas;
          var $cont = canvas.getSize();
          var cameraPos = canvas.getPos();
          var ox = canvas.translateOffsetX;
          var oy = canvas.translateOffsetY;
          var sx = canvas.scaleOffsetX;
          var sy = canvas.scaleOffsetY;
          var pos = $.event.getPos(prop, win);
          this.pos = {
            x : (pos.x - cameraPos.x - $cont.width / 2 - ox) * 1 / sx,
            y : (pos.y - cameraPos.y - $cont.height / 2 - oy) * 1 / sy
          };
          return this.pos;
        },
        /**
         * @return {?}
         */
        getNode : function() {
          if (this.getNodeCalled) {
            return this.node;
          }
          /** @type {boolean} */
          this.getNodeCalled = true;
          var id;
          for (id in graph.nodes) {
            var n = graph.nodes[id];
            var geom = n && ntypes[n.getData("type")];
            var contains = geom && (geom.contains && geom.contains.call(fx, n, this.getPos()));
            if (contains) {
              this.contains = contains;
              return that.node = this.node = n;
            }
          }
          return that.node = this.node = false;
        },
        /**
         * @return {?}
         */
        getEdge : function() {
          if (this.getEdgeCalled) {
            return this.edge;
          }
          /** @type {boolean} */
          this.getEdgeCalled = true;
          var hashset = {};
          var id;
          for (id in graph.edges) {
            var edgeFrom = graph.edges[id];
            /** @type {boolean} */
            hashset[id] = true;
            var edgeId;
            for (edgeId in edgeFrom) {
              if (edgeId in hashset) {
                continue;
              }
              var e = edgeFrom[edgeId];
              var geom = e && etypes[e.getData("type")];
              var contains = geom && (geom.contains && geom.contains.call(fx, e, this.getPos()));
              if (contains) {
                this.contains = contains;
                return that.edge = this.edge = e;
              }
            }
          }
          return that.edge = this.edge = false;
        },
        /**
         * @return {?}
         */
        getContains : function() {
          if (this.getNodeCalled) {
            return this.contains;
          }
          this.getNode();
          return this.contains;
        }
      };
    }
  });
  var Extras = {
    /**
     * @return {undefined}
     */
    initializeExtras : function() {
      var doh = new Tips(this);
      var that = this;
      $.each(["NodeStyles", "Tips", "Navigation", "Events"], function(k) {
        var obj = new Extras.Classes[k](k, that);
        if (obj.isEnabled()) {
          doh.register(obj);
        }
        if (obj.setAsProperty()) {
          that[k.toLowerCase()] = obj;
        }
      });
    }
  };
  Extras.Classes = {};
  Extras.Classes.Events = new Class({
    Implements : [Events, Aspect],
    /**
     * @return {undefined}
     */
    initializePost : function() {
      this.fx = this.viz.fx;
      this.ntypes = this.viz.fx.nodeTypes;
      this.etypes = this.viz.fx.edgeTypes;
      /** @type {boolean} */
      this.hovered = false;
      /** @type {boolean} */
      this.pressed = false;
      /** @type {boolean} */
      this.touched = false;
      /** @type {boolean} */
      this.touchMoved = false;
      /** @type {boolean} */
      this.moved = false;
    },
    setAsProperty : $.lambda(true),
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @param {?} type
     * @return {undefined}
     */
    onMouseUp : function(adj, lab, event, type) {
      var qualifier = $.event.get(adj, lab);
      if (!this.moved) {
        if (type) {
          this.config.onRightClick(this.hovered, event, qualifier);
        } else {
          this.config.onClick(this.pressed, event, qualifier);
        }
      }
      if (this.pressed) {
        if (this.moved) {
          this.config.onDragEnd(this.pressed, event, qualifier);
        } else {
          this.config.onDragCancel(this.pressed, event, qualifier);
        }
        /** @type {boolean} */
        this.pressed = this.moved = false;
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onMouseOut : function(adj, lab, event) {
      var qualifier = $.event.get(adj, lab);
      var label;
      if (this.dom && (label = this.isLabel(adj, lab, true))) {
        this.config.onMouseLeave(this.viz.graph.getNode(label.id), event, qualifier);
        /** @type {boolean} */
        this.hovered = false;
        return;
      }
      var rt = qualifier.relatedTarget;
      var canvasWidget = this.canvas.getElement();
      for (;rt && rt.parentNode;) {
        if (canvasWidget == rt.parentNode) {
          return;
        }
        rt = rt.parentNode;
      }
      if (this.hovered) {
        this.config.onMouseLeave(this.hovered, event, qualifier);
        /** @type {boolean} */
        this.hovered = false;
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onMouseOver : function(adj, lab, event) {
      var qualifier = $.event.get(adj, lab);
      var label;
      if (this.dom && (label = this.isLabel(adj, lab, true))) {
        this.hovered = this.viz.graph.getNode(label.id);
        this.config.onMouseEnter(this.hovered, event, qualifier);
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onMouseMove : function(adj, lab, event) {
      var x;
      var qualifier = $.event.get(adj, lab);
      if (this.pressed) {
        /** @type {boolean} */
        this.moved = true;
        this.config.onDragMove(this.pressed, event, qualifier);
        return;
      }
      if (this.dom) {
        this.config.onMouseMove(this.hovered, event, qualifier);
      } else {
        if (this.hovered) {
          var from = this.hovered;
          var geom = from.nodeFrom ? this.etypes[from.getData("type")] : this.ntypes[from.getData("type")];
          var contains = geom && (geom.contains && geom.contains.call(this.fx, from, event.getPos()));
          if (contains) {
            this.config.onMouseMove(from, event, qualifier);
            return;
          } else {
            this.config.onMouseLeave(from, event, qualifier);
            /** @type {boolean} */
            this.hovered = false;
          }
        }
        if (this.hovered = event.getNode() || this.config.enableForEdges && event.getEdge()) {
          this.config.onMouseEnter(this.hovered, event, qualifier);
        } else {
          this.config.onMouseMove(false, event, qualifier);
        }
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} from
     * @return {undefined}
     */
    onMouseWheel : function(adj, lab, from) {
      this.config.onMouseWheel(from, $.event.get(adj, lab));
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onMouseDown : function(adj, lab, event) {
      var qualifier = $.event.get(adj, lab);
      var label;
      if (this.dom) {
        if (label = this.isLabel(adj, lab)) {
          this.pressed = this.viz.graph.getNode(label.id);
        }
      } else {
        this.pressed = event.getNode() || this.config.enableForEdges && event.getEdge();
      }
      if (this.pressed) {
        this.config.onDragStart(this.pressed, event, qualifier);
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onTouchStart : function(adj, lab, event) {
      var qualifier = $.event.get(adj, lab);
      var label;
      if (this.dom && (label = this.isLabel(adj, lab))) {
        this.touched = this.viz.graph.getNode(label.id);
      } else {
        this.touched = event.getNode() || this.config.enableForEdges && event.getEdge();
      }
      if (this.touched) {
        this.config.onTouchStart(this.touched, event, qualifier);
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onTouchMove : function(adj, lab, event) {
      var qualifier = $.event.get(adj, lab);
      if (this.touched) {
        /** @type {boolean} */
        this.touchMoved = true;
        this.config.onTouchMove(this.touched, event, qualifier);
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onTouchEnd : function(adj, lab, event) {
      var qualifier = $.event.get(adj, lab);
      if (this.touched) {
        if (this.touchMoved) {
          this.config.onTouchEnd(this.touched, event, qualifier);
        } else {
          this.config.onTouchCancel(this.touched, event, qualifier);
        }
        /** @type {boolean} */
        this.touched = this.touchMoved = false;
      }
    }
  });
  Extras.Classes.Tips = new Class({
    Implements : [Events, Aspect],
    /**
     * @return {undefined}
     */
    initializePost : function() {
      if (document.body) {
        var tip = $("_tooltip") || document.createElement("div");
        /** @type {string} */
        tip.id = "_tooltip";
        /** @type {string} */
        tip.className = "tip";
        $.extend(tip.style, {
          position : "absolute",
          display : "none",
          zIndex : 13E3
        });
        document.body.appendChild(tip);
        this.tip = tip;
        /** @type {boolean} */
        this.node = false;
      }
    },
    setAsProperty : $.lambda(true),
    /**
     * @param {?} adj
     * @param {?} lab
     * @return {undefined}
     */
    onMouseOut : function(adj, lab) {
      var orn = $.event.get(adj, lab);
      if (this.dom && this.isLabel(adj, lab, true)) {
        this.hide(true);
        return;
      }
      var rt = adj.relatedTarget;
      var canvasWidget = this.canvas.getElement();
      for (;rt && rt.parentNode;) {
        if (canvasWidget == rt.parentNode) {
          return;
        }
        rt = rt.parentNode;
      }
      this.hide(false);
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @return {undefined}
     */
    onMouseOver : function(adj, lab) {
      var qualifier;
      if (this.dom && (qualifier = this.isLabel(adj, lab, false))) {
        this.node = this.viz.graph.getNode(qualifier.id);
        this.config.onShow(this.tip, this.node, qualifier);
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onMouseMove : function(adj, lab, event) {
      if (this.dom && this.isLabel(adj, lab)) {
        this.setTooltipPosition($.event.getPos(adj, lab));
      }
      if (!this.dom) {
        var cycle = event.getNode();
        if (!cycle) {
          this.hide(true);
          return;
        }
        if (this.config.force || (!this.node || this.node.id != cycle.id)) {
          this.node = cycle;
          this.config.onShow(this.tip, cycle, event.getContains());
        }
        this.setTooltipPosition($.event.getPos(adj, lab));
      }
    },
    /**
     * @param {?} pos
     * @return {undefined}
     */
    setTooltipPosition : function(pos) {
      var tip = this.tip;
      var style = tip.style;
      var cont = this.config;
      /** @type {string} */
      style.display = "";
      var win = {
        height : document.body.clientHeight,
        width : document.body.clientWidth
      };
      var obj = {
        width : tip.offsetWidth,
        height : tip.offsetHeight
      };
      var x = cont.offsetX;
      var y = cont.offsetY;
      /** @type {string} */
      style.top = (pos.y + y + obj.height > win.height ? pos.y - obj.height - y : pos.y + y) + "px";
      /** @type {string} */
      style.left = (pos.x + obj.width + x > win.width ? pos.x - obj.width - x : pos.x + x) + "px";
    },
    /**
     * @param {boolean} recurring
     * @return {undefined}
     */
    hide : function(recurring) {
      /** @type {string} */
      this.tip.style.display = "none";
      if (recurring) {
        this.config.onHide();
      }
    }
  });
  Extras.Classes.NodeStyles = new Class({
    Implements : [Events, Aspect],
    /**
     * @return {undefined}
     */
    initializePost : function() {
      this.fx = this.viz.fx;
      this.types = this.viz.fx.nodeTypes;
      this.nStyles = this.config;
      this.nodeStylesOnHover = this.nStyles.stylesHover;
      this.nodeStylesOnClick = this.nStyles.stylesClick;
      /** @type {boolean} */
      this.hoveredNode = false;
      this.fx.nodeFxAnimation = new Animation;
      /** @type {boolean} */
      this.down = false;
      /** @type {boolean} */
      this.move = false;
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @return {undefined}
     */
    onMouseOut : function(adj, lab) {
      /** @type {boolean} */
      this.down = this.move = false;
      if (!this.hoveredNode) {
        return;
      }
      if (this.dom && this.isLabel(adj, lab, true)) {
        this.toggleStylesOnHover(this.hoveredNode, false);
      }
      var rt = adj.relatedTarget;
      var canvasWidget = this.canvas.getElement();
      for (;rt && rt.parentNode;) {
        if (canvasWidget == rt.parentNode) {
          return;
        }
        rt = rt.parentNode;
      }
      this.toggleStylesOnHover(this.hoveredNode, false);
      /** @type {boolean} */
      this.hoveredNode = false;
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @return {undefined}
     */
    onMouseOver : function(adj, lab) {
      var label;
      if (this.dom && (label = this.isLabel(adj, lab, true))) {
        var node = this.viz.graph.getNode(label.id);
        if (node.selected) {
          return;
        }
        this.hoveredNode = node;
        this.toggleStylesOnHover(this.hoveredNode, true);
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @param {?} type
     * @return {undefined}
     */
    onMouseDown : function(adj, lab, event, type) {
      if (type) {
        return;
      }
      var label;
      if (this.dom && (label = this.isLabel(adj, lab))) {
        this.down = this.viz.graph.getNode(label.id);
      } else {
        if (!this.dom) {
          this.down = event.getNode();
        }
      }
      /** @type {boolean} */
      this.move = false;
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @param {?} type
     * @return {undefined}
     */
    onMouseUp : function(adj, lab, event, type) {
      if (type) {
        return;
      }
      if (!this.move) {
        this.onClick(event.getNode());
      }
      /** @type {boolean} */
      this.down = this.move = false;
    },
    /**
     * @param {Object} node
     * @param {string} type
     * @return {?}
     */
    getRestoredStyles : function(node, type) {
      var restoredStyles = {};
      var source = this["nodeStylesOn" + type];
      var prop;
      for (prop in source) {
        restoredStyles[prop] = node.styles["$" + prop];
      }
      return restoredStyles;
    },
    /**
     * @param {?} node
     * @param {boolean} recurring
     * @return {undefined}
     */
    toggleStylesOnHover : function(node, recurring) {
      if (this.nodeStylesOnHover) {
        this.toggleStylesOn("Hover", node, recurring);
      }
    },
    /**
     * @param {Object} node
     * @param {boolean} recurring
     * @return {undefined}
     */
    toggleStylesOnClick : function(node, recurring) {
      if (this.nodeStylesOnClick) {
        this.toggleStylesOn("Click", node, recurring);
      }
    },
    /**
     * @param {string} type
     * @param {Object} node
     * @param {boolean} recurring
     * @return {undefined}
     */
    toggleStylesOn : function(type, node, recurring) {
      var viz = this.viz;
      var nStyles = this.nStyles;
      if (recurring) {
        var that = this;
        if (!node.styles) {
          node.styles = $.merge(node.data, {});
        }
        var s;
        for (s in this["nodeStylesOn" + type]) {
          /** @type {string} */
          var $s = "$" + s;
          if (!($s in node.styles)) {
            node.styles[$s] = node.getData(s);
          }
        }
        viz.fx.nodeFx($.extend({
          elements : {
            id : node.id,
            properties : that["nodeStylesOn" + type]
          },
          transition : $cookies.Quart.easeOut,
          duration : 300,
          fps : 40
        }, this.config));
      } else {
        var queue = this.getRestoredStyles(node, type);
        viz.fx.nodeFx($.extend({
          elements : {
            id : node.id,
            properties : queue
          },
          transition : $cookies.Quart.easeOut,
          duration : 300,
          fps : 40
        }, this.config));
      }
    },
    /**
     * @param {?} adj
     * @return {undefined}
     */
    onClick : function(adj) {
      if (!adj) {
        return;
      }
      var nStyles = this.nodeStylesOnClick;
      if (!nStyles) {
        return;
      }
      if (adj.selected) {
        this.toggleStylesOnClick(adj, false);
        delete adj.selected;
      } else {
        this.viz.graph.eachNode(function(n) {
          if (n.selected) {
            var s;
            for (s in nStyles) {
              n.setData(s, n.styles["$" + s], "end");
            }
            delete n.selected;
          }
        });
        this.toggleStylesOnClick(adj, true);
        /** @type {boolean} */
        adj.selected = true;
        delete adj.hovered;
        /** @type {boolean} */
        this.hoveredNode = false;
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onMouseMove : function(adj, lab, event) {
      if (this.down) {
        /** @type {boolean} */
        this.move = true;
      }
      if (this.dom && this.isLabel(adj, lab)) {
        return;
      }
      var nStyles = this.nodeStylesOnHover;
      if (!nStyles) {
        return;
      }
      if (!this.dom) {
        if (this.hoveredNode) {
          var geom = this.types[this.hoveredNode.getData("type")];
          var contains = geom && (geom.contains && geom.contains.call(this.fx, this.hoveredNode, event.getPos()));
          if (contains) {
            return;
          }
        }
        var node = event.getNode();
        if (!this.hoveredNode && !node) {
          return;
        }
        if (node.hovered) {
          return;
        }
        if (node && !node.selected) {
          this.fx.nodeFxAnimation.stopTimer();
          this.viz.graph.eachNode(function(n) {
            if (n.hovered && !n.selected) {
              var s;
              for (s in nStyles) {
                n.setData(s, n.styles["$" + s], "end");
              }
              delete n.hovered;
            }
          });
          /** @type {boolean} */
          node.hovered = true;
          this.hoveredNode = node;
          this.toggleStylesOnHover(node, true);
        } else {
          if (this.hoveredNode && !this.hoveredNode.selected) {
            this.fx.nodeFxAnimation.stopTimer();
            this.toggleStylesOnHover(this.hoveredNode, false);
            delete this.hoveredNode.hovered;
            /** @type {boolean} */
            this.hoveredNode = false;
          }
        }
      }
    }
  });
  Extras.Classes.Navigation = new Class({
    Implements : [Events, Aspect],
    /**
     * @return {undefined}
     */
    initializePost : function() {
      /** @type {boolean} */
      this.pos = false;
      /** @type {boolean} */
      this.pressed = false;
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onMouseWheel : function(adj, lab, event) {
      if (!this.config.zooming) {
        return;
      }
      $.event.stop($.event.get(adj, lab));
      /** @type {number} */
      var A = this.config.zooming / 1E3;
      /** @type {number} */
      var scaling = 1 + event * A;
      this.canvas.scale(scaling, scaling);
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onMouseDown : function(adj, lab, event) {
      if (!this.config.panning) {
        return;
      }
      if (this.config.panning == "avoid nodes" && (this.dom ? this.isLabel(adj, lab) : event.getNode())) {
        return;
      }
      /** @type {boolean} */
      this.pressed = true;
      this.pos = event.getPos();
      var canvas = this.canvas;
      var ox = canvas.translateOffsetX;
      var oy = canvas.translateOffsetY;
      var sx = canvas.scaleOffsetX;
      var sy = canvas.scaleOffsetY;
      this.pos.x *= sx;
      this.pos.x += ox;
      this.pos.y *= sy;
      this.pos.y += oy;
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    onMouseMove : function(adj, lab, event) {
      if (!this.config.panning) {
        return;
      }
      if (!this.pressed) {
        return;
      }
      if (this.config.panning == "avoid nodes" && (this.dom ? this.isLabel(adj, lab) : event.getNode())) {
        return;
      }
      var thispos = this.pos;
      var currentPos = event.getPos();
      var canvas = this.canvas;
      var ox = canvas.translateOffsetX;
      var oy = canvas.translateOffsetY;
      var sx = canvas.scaleOffsetX;
      var sy = canvas.scaleOffsetY;
      currentPos.x *= sx;
      currentPos.y *= sy;
      currentPos.x += ox;
      currentPos.y += oy;
      /** @type {number} */
      var x = currentPos.x - thispos.x;
      /** @type {number} */
      var y = currentPos.y - thispos.y;
      this.pos = currentPos;
      this.canvas.translate(x * 1 / sx, y * 1 / sy);
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @param {?} type
     * @return {undefined}
     */
    onMouseUp : function(adj, lab, event, type) {
      if (!this.config.panning) {
        return;
      }
      /** @type {boolean} */
      this.pressed = false;
    }
  });
  var Canvas;
  (function() {
    /**
     * @param {string} tag
     * @param {?} props
     * @return {?}
     */
    function $E(tag, props) {
      /** @type {Element} */
      var elem = document.createElement(tag);
      var name;
      for (name in props) {
        if (typeof props[name] == "object") {
          $.extend(elem[name], props[name]);
        } else {
          elem[name] = props[name];
        }
      }
      if (tag == "canvas" && (!supportsCanvas && G_vmlCanvasManager)) {
        elem = G_vmlCanvasManager.initElement(document.body.appendChild(elem));
      }
      return elem;
    }
    /** @type {string} */
    var typeOfCanvas = typeof HTMLCanvasElement;
    /** @type {boolean} */
    var supportsCanvas = typeOfCanvas == "object" || typeOfCanvas == "function";
    $jit.Canvas = Canvas = new Class({
      canvases : [],
      pos : false,
      element : false,
      labelContainer : false,
      translateOffsetX : 0,
      translateOffsetY : 0,
      scaleOffsetX : 1,
      scaleOffsetY : 1,
      /**
       * @param {Object} viz
       * @param {Object} opt
       * @return {undefined}
       */
      initialize : function(viz, opt) {
        /** @type {Object} */
        this.viz = viz;
        this.opt = this.config = opt;
        var id = $.type(opt.injectInto) == "string" ? opt.injectInto : opt.injectInto.id;
        var type = opt.type;
        /** @type {string} */
        var idLabel = id + "-label";
        var wrapper = $(id);
        var originalWidth = opt.width || wrapper.offsetWidth;
        var _height = opt.height || wrapper.offsetHeight;
        this.id = id;
        var canvasOptions = {
          injectInto : id,
          width : originalWidth,
          height : _height
        };
        this.element = $E("div", {
          id : id + "-canvaswidget",
          style : {
            position : "relative",
            width : originalWidth + "px",
            height : _height + "px"
          }
        });
        this.labelContainer = this.createLabelContainer(opt.Label.type, idLabel, canvasOptions);
        this.canvases.push(new Canvas.Base[type]({
          config : $.extend({
            idSuffix : "-canvas"
          }, canvasOptions),
          /**
           * @param {?} opt
           * @return {undefined}
           */
          plot : function(opt) {
            viz.fx.plot();
          },
          /**
           * @return {undefined}
           */
          resize : function() {
            viz.refresh();
          }
        }));
        var back = opt.background;
        if (back) {
          var backCanvas = new Canvas.Background[back.type](viz, $.extend(back, canvasOptions));
          this.canvases.push(new Canvas.Base[type](backCanvas));
        }
        var len = this.canvases.length;
        for (;len--;) {
          this.element.appendChild(this.canvases[len].canvas);
          if (len > 0) {
            this.canvases[len].plot();
          }
        }
        this.element.appendChild(this.labelContainer);
        wrapper.appendChild(this.element);
        /** @type {null} */
        var tref = null;
        var f = this;
        $.addEvent(window, "scroll", function() {
          clearTimeout(tref);
          /** @type {number} */
          tref = setTimeout(function() {
            f.getPos(true);
          }, 500);
        });
      },
      /**
       * @param {number} i
       * @return {?}
       */
      getCtx : function(i) {
        return this.canvases[i || 0].getCtx();
      },
      /**
       * @return {?}
       */
      getConfig : function() {
        return this.opt;
      },
      /**
       * @return {?}
       */
      getElement : function() {
        return this.element;
      },
      /**
       * @param {number} dataAndEvents
       * @return {?}
       */
      getSize : function(dataAndEvents) {
        return this.canvases[dataAndEvents || 0].getSize();
      },
      /**
       * @param {number} w
       * @param {number} height
       * @return {undefined}
       */
      resize : function(w, height) {
        this.getPos(true);
        /** @type {number} */
        this.translateOffsetX = this.translateOffsetY = 0;
        /** @type {number} */
        this.scaleOffsetX = this.scaleOffsetY = 1;
        /** @type {number} */
        var i = 0;
        var l = this.canvases.length;
        for (;i < l;i++) {
          this.canvases[i].resize(w, height);
        }
        var style = this.element.style;
        /** @type {string} */
        style.width = w + "px";
        /** @type {string} */
        style.height = height + "px";
        if (this.labelContainer) {
          /** @type {string} */
          this.labelContainer.style.width = w + "px";
        }
      },
      /**
       * @param {number} x
       * @param {number} y
       * @param {boolean} z
       * @return {undefined}
       */
      translate : function(x, y, z) {
        this.translateOffsetX += x * this.scaleOffsetX;
        this.translateOffsetY += y * this.scaleOffsetY;
        /** @type {number} */
        var i = 0;
        var l = this.canvases.length;
        for (;i < l;i++) {
          this.canvases[i].translate(x, y, z);
        }
      },
      /**
       * @param {number} x
       * @param {number} y
       * @param {boolean} dataAndEvents
       * @return {undefined}
       */
      scale : function(x, y, dataAndEvents) {
        /** @type {number} */
        var px = this.scaleOffsetX * x;
        /** @type {number} */
        var py = this.scaleOffsetY * y;
        /** @type {number} */
        var ll = this.translateOffsetX * (x - 1) / px;
        /** @type {number} */
        var dy = this.translateOffsetY * (y - 1) / py;
        /** @type {number} */
        this.scaleOffsetX = px;
        /** @type {number} */
        this.scaleOffsetY = py;
        /** @type {number} */
        var i = 0;
        var l = this.canvases.length;
        for (;i < l;i++) {
          this.canvases[i].scale(x, y, true);
        }
        this.translate(ll, dy, false);
      },
      /**
       * @param {boolean} expectation
       * @return {?}
       */
      getPos : function(expectation) {
        if (expectation || !this.pos) {
          return this.pos = $.getPos(this.getElement());
        }
        return this.pos;
      },
      /**
       * @param {number} arr
       * @return {undefined}
       */
      clear : function(arr) {
        this.canvases[arr || 0].clear();
      },
      /**
       * @param {?} id
       * @param {?} callback
       * @return {undefined}
       */
      path : function(id, callback) {
        var me = this.canvases[0].getCtx();
        me.beginPath();
        callback(me);
        me[id]();
        me.closePath();
      },
      /**
       * @param {string} type
       * @param {string} idLabel
       * @param {?} dim
       * @return {?}
       */
      createLabelContainer : function(type, idLabel, dim) {
        /** @type {string} */
        var NS = "http://www.w3.org/2000/svg";
        if (type == "HTML" || type == "Native") {
          return $E("div", {
            id : idLabel,
            style : {
              overflow : "visible",
              position : "absolute",
              top : 0,
              left : 0,
              width : dim.width + "px",
              height : 0
            }
          });
        } else {
          if (type == "SVG") {
            /** @type {Element} */
            var svgContainer = document.createElementNS(NS, "svg:svg");
            svgContainer.setAttribute("width", dim.width);
            svgContainer.setAttribute("height", dim.height);
            /** @type {(CSSStyleDeclaration|null)} */
            var style = svgContainer.style;
            /** @type {string} */
            style.position = "absolute";
            /** @type {string} */
            style.left = style.top = "0px";
            /** @type {Element} */
            var labelContainer = document.createElementNS(NS, "svg:g");
            labelContainer.setAttribute("width", dim.width);
            labelContainer.setAttribute("height", dim.height);
            labelContainer.setAttribute("x", 0);
            labelContainer.setAttribute("y", 0);
            labelContainer.setAttribute("id", idLabel);
            svgContainer.appendChild(labelContainer);
            return svgContainer;
          }
        }
      }
    });
    Canvas.Base = {};
    Canvas.Base["2D"] = new Class({
      translateOffsetX : 0,
      translateOffsetY : 0,
      scaleOffsetX : 1,
      scaleOffsetY : 1,
      /**
       * @param {?} viz
       * @return {undefined}
       */
      initialize : function(viz) {
        this.viz = viz;
        this.opt = viz.config;
        /** @type {boolean} */
        this.size = false;
        this.createCanvas();
        this.translateToCenter();
      },
      /**
       * @return {undefined}
       */
      createCanvas : function() {
        var opt = this.opt;
        var width = opt.width;
        var h = opt.height;
        this.canvas = $E("canvas", {
          id : opt.injectInto + opt.idSuffix,
          width : width,
          height : h,
          style : {
            position : "absolute",
            top : 0,
            left : 0,
            width : width + "px",
            height : h + "px"
          }
        });
      },
      /**
       * @return {?}
       */
      getCtx : function() {
        if (!this.ctx) {
          return this.ctx = this.canvas.getContext("2d");
        }
        return this.ctx;
      },
      /**
       * @return {?}
       */
      getSize : function() {
        if (this.size) {
          return this.size;
        }
        var canvas = this.canvas;
        return this.size = {
          width : canvas.width,
          height : canvas.height
        };
      },
      /**
       * @param {boolean} ps
       * @return {undefined}
       */
      translateToCenter : function(ps) {
        var size = this.getSize();
        var width = ps ? size.width - ps.width - this.translateOffsetX * 2 : size.width;
        height = ps ? size.height - ps.height - this.translateOffsetY * 2 : size.height;
        var ctx = this.getCtx();
        if (ps) {
          ctx.scale(1 / this.scaleOffsetX, 1 / this.scaleOffsetY);
        }
        ctx.translate(width / 2, height / 2);
      },
      /**
       * @param {number} width
       * @param {number} height
       * @return {undefined}
       */
      resize : function(width, height) {
        var size = this.getSize();
        var canvas = this.canvas;
        var style = canvas.style;
        /** @type {boolean} */
        this.size = false;
        /** @type {number} */
        canvas.width = width;
        /** @type {number} */
        canvas.height = height;
        /** @type {string} */
        style.width = width + "px";
        /** @type {string} */
        style.height = height + "px";
        if (!supportsCanvas) {
          this.translateToCenter(size);
        } else {
          this.translateToCenter();
        }
        /** @type {number} */
        this.translateOffsetX = this.translateOffsetY = 0;
        /** @type {number} */
        this.scaleOffsetX = this.scaleOffsetY = 1;
        this.clear();
        this.viz.resize(width, height, this);
      },
      /**
       * @param {number} x
       * @param {number} y
       * @param {boolean} z
       * @return {undefined}
       */
      translate : function(x, y, z) {
        var sx = this.scaleOffsetX;
        var sy = this.scaleOffsetY;
        this.translateOffsetX += x * sx;
        this.translateOffsetY += y * sy;
        this.getCtx().translate(x, y);
        if (!z) {
          this.plot();
        }
      },
      /**
       * @param {number} x
       * @param {number} y
       * @param {boolean} dataAndEvents
       * @return {undefined}
       */
      scale : function(x, y, dataAndEvents) {
        this.scaleOffsetX *= x;
        this.scaleOffsetY *= y;
        this.getCtx().scale(x, y);
        if (!dataAndEvents) {
          this.plot();
        }
      },
      /**
       * @return {undefined}
       */
      clear : function() {
        var size = this.getSize();
        var ox = this.translateOffsetX;
        var oy = this.translateOffsetY;
        var sx = this.scaleOffsetX;
        var sy = this.scaleOffsetY;
        this.getCtx().clearRect((-size.width / 2 - ox) * 1 / sx, (-size.height / 2 - oy) * 1 / sy, size.width * 1 / sx, size.height * 1 / sy);
      },
      /**
       * @return {undefined}
       */
      plot : function() {
        this.clear();
        this.viz.plot(this);
      }
    });
    Canvas.Background = {};
    Canvas.Background.Circles = new Class({
      /**
       * @param {?} viz
       * @param {?} options
       * @return {undefined}
       */
      initialize : function(viz, options) {
        this.viz = viz;
        this.config = $.merge({
          idSuffix : "-bkcanvas",
          levelDistance : 100,
          numberOfCircles : 6,
          CanvasStyles : {},
          offset : 0
        }, options);
      },
      /**
       * @param {number} w
       * @param {number} height
       * @param {?} opt
       * @return {undefined}
       */
      resize : function(w, height, opt) {
        this.plot(opt);
      },
      /**
       * @param {?} base
       * @return {undefined}
       */
      plot : function(base) {
        var canvas = base.canvas;
        var ctx = base.getCtx();
        var conf = this.config;
        var styles = conf.CanvasStyles;
        var s;
        for (s in styles) {
          ctx[s] = styles[s];
        }
        var n = conf.numberOfCircles;
        var rho = conf.levelDistance;
        /** @type {number} */
        var i = 1;
        for (;i <= n;i++) {
          ctx.beginPath();
          ctx.arc(0, 0, rho * i, 0, 2 * Math.PI, false);
          ctx.stroke();
          ctx.closePath();
        }
      }
    });
  })();
  /**
   * @param {number} v
   * @param {number} str
   * @return {undefined}
   */
  var Transform = function(v, str) {
    this.theta = v || 0;
    this.rho = str || 0;
  };
  /** @type {function (number, number): undefined} */
  $jit.Polar = Transform;
  Transform.prototype = {
    /**
     * @param {boolean} dataAndEvents
     * @return {?}
     */
    getc : function(dataAndEvents) {
      return this.toComplex(dataAndEvents);
    },
    /**
     * @return {?}
     */
    getp : function() {
      return this;
    },
    /**
     * @param {?} item
     * @return {undefined}
     */
    set : function(item) {
      item = item.getp();
      this.theta = item.theta;
      this.rho = item.rho;
    },
    /**
     * @param {number} x
     * @param {number} y
     * @return {undefined}
     */
    setc : function(x, y) {
      /** @type {number} */
      this.rho = Math.sqrt(x * x + y * y);
      /** @type {number} */
      this.theta = Math.atan2(y, x);
      if (this.theta < 0) {
        this.theta += Math.PI * 2;
      }
    },
    /**
     * @param {number} theta
     * @param {?} dataAndEvents
     * @return {undefined}
     */
    setp : function(theta, dataAndEvents) {
      /** @type {number} */
      this.theta = theta;
      this.rho = dataAndEvents;
    },
    /**
     * @return {?}
     */
    clone : function() {
      return new Transform(this.theta, this.rho);
    },
    /**
     * @param {boolean} dataAndEvents
     * @return {?}
     */
    toComplex : function(dataAndEvents) {
      /** @type {number} */
      var ex = Math.cos(this.theta) * this.rho;
      /** @type {number} */
      var py = Math.sin(this.theta) * this.rho;
      if (dataAndEvents) {
        return{
          x : ex,
          y : py
        };
      }
      return new Vector(ex, py);
    },
    /**
     * @param {?} v2
     * @return {?}
     */
    add : function(v2) {
      return new Transform(this.theta + v2.theta, this.rho + v2.rho);
    },
    /**
     * @param {number} x
     * @return {?}
     */
    scale : function(x) {
      return new Transform(this.theta, this.rho * x);
    },
    /**
     * @param {?} item
     * @return {?}
     */
    equals : function(item) {
      return this.theta == item.theta && this.rho == item.rho;
    },
    /**
     * @param {number} item
     * @return {?}
     */
    $add : function(item) {
      this.theta = this.theta + item.theta;
      this.rho += item.rho;
      return this;
    },
    /**
     * @param {?} item
     * @return {?}
     */
    $madd : function(item) {
      /** @type {number} */
      this.theta = (this.theta + item.theta) % (Math.PI * 2);
      this.rho += item.rho;
      return this;
    },
    /**
     * @param {number} opt_attributes
     * @return {?}
     */
    $scale : function(opt_attributes) {
      this.rho *= opt_attributes;
      return this;
    },
    /**
     * @return {?}
     */
    isZero : function() {
      /** @type {number} */
      var distance = 1E-4;
      /** @type {function (*): number} */
      var abs = Math.abs;
      return abs(this.theta) < distance && abs(this.rho) < distance;
    },
    /**
     * @param {?} item
     * @param {number} x
     * @return {?}
     */
    interpolate : function(item, x) {
      /** @type {number} */
      var end = Math.PI;
      /** @type {number} */
      var base = end * 2;
      /**
       * @param {number} n
       * @return {?}
       */
      var toString = function(n) {
        /** @type {number} */
        var callStr = n < 0 ? n % base + base : n % base;
        return callStr;
      };
      var a = this.theta;
      var b = item.theta;
      var str;
      /** @type {number} */
      var start = Math.abs(a - b);
      if (start == end) {
        if (a > b) {
          str = toString(b + (a - base - b) * x);
        } else {
          str = toString(b - base + (a - b) * x);
        }
      } else {
        if (start >= end) {
          if (a > b) {
            str = toString(b + (a - base - b) * x);
          } else {
            str = toString(b - base + (a - (b - base)) * x);
          }
        } else {
          str = toString(b + (a - b) * x);
        }
      }
      var rho = (this.rho - item.rho) * x + item.rho;
      return{
        theta : str,
        rho : rho
      };
    }
  };
  /**
   * @param {number} x
   * @param {number} recurring
   * @return {?}
   */
  var $P = function(x, recurring) {
    return new Transform(x, recurring);
  };
  Transform.KER = $P(0, 0);
  /**
   * @param {number} x
   * @param {(number|string)} y
   * @return {undefined}
   */
  var Vector = function(x, y) {
    this.x = x || 0;
    this.y = y || 0;
  };
  /** @type {function (number, (number|string)): undefined} */
  $jit.Complex = Vector;
  Vector.prototype = {
    /**
     * @return {?}
     */
    getc : function() {
      return this;
    },
    /**
     * @param {boolean} deepDataAndEvents
     * @return {?}
     */
    getp : function(deepDataAndEvents) {
      return this.toPolar(deepDataAndEvents);
    },
    /**
     * @param {?} pos
     * @return {undefined}
     */
    set : function(pos) {
      pos = pos.getc(true);
      this.x = pos.x;
      this.y = pos.y;
    },
    /**
     * @param {number} x1
     * @param {?} y
     * @return {undefined}
     */
    setc : function(x1, y) {
      /** @type {number} */
      this.x = x1;
      this.y = y;
    },
    /**
     * @param {?} theta2
     * @param {number} fact
     * @return {undefined}
     */
    setp : function(theta2, fact) {
      /** @type {number} */
      this.x = Math.cos(theta2) * fact;
      /** @type {number} */
      this.y = Math.sin(theta2) * fact;
    },
    /**
     * @return {?}
     */
    clone : function() {
      return new Vector(this.x, this.y);
    },
    /**
     * @param {boolean} deepDataAndEvents
     * @return {?}
     */
    toPolar : function(deepDataAndEvents) {
      var rho = this.norm();
      /** @type {number} */
      var x = Math.atan2(this.y, this.x);
      if (x < 0) {
        x += Math.PI * 2;
      }
      if (deepDataAndEvents) {
        return{
          theta : x,
          rho : rho
        };
      }
      return new Transform(x, rho);
    },
    /**
     * @return {?}
     */
    norm : function() {
      return Math.sqrt(this.squaredNorm());
    },
    /**
     * @return {?}
     */
    squaredNorm : function() {
      return this.x * this.x + this.y * this.y;
    },
    /**
     * @param {?} v2
     * @return {?}
     */
    add : function(v2) {
      return new Vector(this.x + v2.x, this.y + v2.y);
    },
    /**
     * @param {?} v
     * @return {?}
     */
    prod : function(v) {
      return new Vector(this.x * v.x - this.y * v.y, this.y * v.x + this.x * v.y);
    },
    /**
     * @return {?}
     */
    conjugate : function() {
      return new Vector(this.x, -this.y);
    },
    /**
     * @param {number} n
     * @return {?}
     */
    scale : function(n) {
      return new Vector(this.x * n, this.y * n);
    },
    /**
     * @param {?} other
     * @return {?}
     */
    equals : function(other) {
      return this.x == other.x && this.y == other.y;
    },
    /**
     * @param {number} vec
     * @return {?}
     */
    $add : function(vec) {
      this.x += vec.x;
      this.y += vec.y;
      return this;
    },
    /**
     * @param {?} c
     * @return {?}
     */
    $prod : function(c) {
      var x = this.x;
      var y = this.y;
      /** @type {number} */
      this.x = x * c.x - y * c.y;
      /** @type {number} */
      this.y = y * c.x + x * c.y;
      return this;
    },
    /**
     * @return {?}
     */
    $conjugate : function() {
      /** @type {number} */
      this.y = -this.y;
      return this;
    },
    /**
     * @param {number} opt_attributes
     * @return {?}
     */
    $scale : function(opt_attributes) {
      this.x *= opt_attributes;
      this.y *= opt_attributes;
      return this;
    },
    /**
     * @param {?} p
     * @return {?}
     */
    $div : function(p) {
      var x = this.x;
      var y = this.y;
      var z = p.squaredNorm();
      /** @type {number} */
      this.x = x * p.x + y * p.y;
      /** @type {number} */
      this.y = y * p.x - x * p.y;
      return this.$scale(1 / z);
    },
    /**
     * @return {?}
     */
    isZero : function() {
      /** @type {number} */
      var distance = 1E-4;
      /** @type {function (*): number} */
      var abs = Math.abs;
      return abs(this.x) < distance && abs(this.y) < distance;
    }
  };
  /**
   * @param {number} recurring
   * @param {number} mayParseLabeledStatementInstead
   * @return {?}
   */
  var getIndex = function(recurring, mayParseLabeledStatementInstead) {
    return new Vector(recurring, mayParseLabeledStatementInstead);
  };
  Vector.KER = getIndex(0, 0);
  $jit.Graph = new Class({
    /**
     * @param {Object} options
     * @param {?} Node
     * @param {?} Edge
     * @param {?} Label
     * @return {undefined}
     */
    initialize : function(options, Node, Edge, Label) {
      var innerOptions = {
        /** @type {function (number, (number|string)): undefined} */
        klass : Vector,
        Node : {}
      };
      this.Node = Node;
      this.Edge = Edge;
      this.Label = Label;
      this.opt = $.merge(innerOptions, options || {});
      this.nodes = {};
      this.edges = {};
      var that = this;
      this.nodeList = {};
      var i;
      for (i in methods) {
        that.nodeList[i] = function(method) {
          return function() {
            /** @type {Array.<?>} */
            var args = Array.prototype.slice.call(arguments);
            that.eachNode(function(reporter) {
              reporter[method].apply(reporter, args);
            });
          };
        }(i);
      }
    },
    /**
     * @param {?} id
     * @return {?}
     */
    getNode : function(id) {
      if (this.hasNode(id)) {
        return this.nodes[id];
      }
      return false;
    },
    /**
     * @param {?} adj
     * @return {?}
     */
    get : function(adj) {
      return this.getNode(adj);
    },
    /**
     * @param {?} name
     * @return {?}
     */
    getByName : function(name) {
      var i2;
      for (i2 in this.nodes) {
        var n = this.nodes[i2];
        if (n.name == name) {
          return n;
        }
      }
      return false;
    },
    /**
     * @param {?} id
     * @param {?} id2
     * @return {?}
     */
    getAdjacence : function(id, id2) {
      if (id in this.edges) {
        return this.edges[id][id2];
      }
      return false;
    },
    /**
     * @param {Object} obj
     * @return {?}
     */
    addNode : function(obj) {
      if (!this.nodes[obj.id]) {
        var edges = this.edges[obj.id] = {};
        this.nodes[obj.id] = new Graph.Node($.extend({
          id : obj.id,
          name : obj.name,
          data : $.merge(obj.data || {}, {}),
          adjacencies : edges
        }, this.opt.Node), this.opt.klass, this.Node, this.Edge, this.Label);
      }
      return this.nodes[obj.id];
    },
    /**
     * @param {Object} obj
     * @param {number} obj2
     * @param {number} data
     * @return {?}
     */
    addAdjacence : function(obj, obj2, data) {
      if (!this.hasNode(obj.id)) {
        this.addNode(obj);
      }
      if (!this.hasNode(obj2.id)) {
        this.addNode(obj2);
      }
      obj = this.nodes[obj.id];
      obj2 = this.nodes[obj2.id];
      if (!obj.adjacentTo(obj2)) {
        var adjsObj = this.edges[obj.id] = this.edges[obj.id] || {};
        var adjsObj2 = this.edges[obj2.id] = this.edges[obj2.id] || {};
        adjsObj[obj2.id] = adjsObj2[obj.id] = new Graph.Adjacence(obj, obj2, data, this.Edge, this.Label);
        return adjsObj[obj2.id];
      }
      return this.edges[obj.id][obj2.id];
    },
    /**
     * @param {Array} id
     * @return {undefined}
     */
    removeNode : function(id) {
      if (this.hasNode(id)) {
        delete this.nodes[id];
        var adjs = this.edges[id];
        var to;
        for (to in adjs) {
          delete this.edges[to][id];
        }
        delete this.edges[id];
      }
    },
    /**
     * @param {?} id2
     * @param {?} id1
     * @return {undefined}
     */
    removeAdjacence : function(id2, id1) {
      delete this.edges[id2][id1];
      delete this.edges[id1][id2];
    },
    /**
     * @param {?} id
     * @return {?}
     */
    hasNode : function(id) {
      return id in this.nodes;
    },
    /**
     * @return {undefined}
     */
    empty : function() {
      this.nodes = {};
      this.edges = {};
    }
  });
  var Graph = $jit.Graph;
  var methods;
  (function() {
    /**
     * @param {string} prefix
     * @param {number} prop
     * @param {string} type
     * @param {?} force
     * @param {Array} prefixConfig
     * @return {?}
     */
    var getDataInternal = function(prefix, prop, type, force, prefixConfig) {
      var data;
      type = type || "current";
      /** @type {string} */
      prefix = "$" + (prefix ? prefix + "-" : "");
      if (type == "current") {
        data = this.data;
      } else {
        if (type == "start") {
          data = this.startData;
        } else {
          if (type == "end") {
            data = this.endData;
          }
        }
      }
      /** @type {string} */
      var dollar = prefix + prop;
      if (force) {
        return data[dollar];
      }
      if (!this.Config.overridable) {
        return prefixConfig[prop] || 0;
      }
      return dollar in data ? data[dollar] : dollar in this.data ? this.data[dollar] : prefixConfig[prop] || 0;
    };
    /**
     * @param {string} prefix
     * @param {string} prop
     * @param {?} value
     * @param {string} type
     * @return {undefined}
     */
    var setDataInternal = function(prefix, prop, value, type) {
      type = type || "current";
      /** @type {string} */
      prefix = "$" + (prefix ? prefix + "-" : "");
      var data;
      if (type == "current") {
        data = this.data;
      } else {
        if (type == "start") {
          data = this.startData;
        } else {
          if (type == "end") {
            data = this.endData;
          }
        }
      }
      data[prefix + prop] = value;
    };
    /**
     * @param {string} prefix
     * @param {?} attributes
     * @return {undefined}
     */
    var removeDataInternal = function(prefix, attributes) {
      /** @type {string} */
      prefix = "$" + (prefix ? prefix + "-" : "");
      var that = this;
      $.each(attributes, function(t) {
        var pref = prefix + t;
        delete that.data[pref];
        delete that.endData[pref];
        delete that.startData[pref];
      });
    };
    methods = {
      /**
       * @param {string} x
       * @param {Object} callback
       * @param {?} force
       * @return {?}
       */
      getData : function(x, callback, force) {
        return getDataInternal.call(this, "", x, callback, force, this.Config);
      },
      /**
       * @param {string} prop
       * @param {number} recurring
       * @param {string} callback
       * @return {undefined}
       */
      setData : function(prop, recurring, callback) {
        setDataInternal.call(this, "", prop, recurring, callback);
      },
      /**
       * @param {(Array|string)} types
       * @param {?} obj
       * @return {undefined}
       */
      setDataset : function(types, obj) {
        types = $.splat(types);
        var attr;
        for (attr in obj) {
          /** @type {number} */
          var i = 0;
          var prevSources = $.splat(obj[attr]);
          var valuesLen = types.length;
          for (;i < valuesLen;i++) {
            this.setData(attr, prevSources[i], types[i]);
          }
        }
      },
      /**
       * @return {undefined}
       */
      removeData : function() {
        removeDataInternal.call(this, "", Array.prototype.slice.call(arguments));
      },
      /**
       * @param {string} prop
       * @param {?} type
       * @param {?} force
       * @return {?}
       */
      getCanvasStyle : function(prop, type, force) {
        return getDataInternal.call(this, "canvas", prop, type, force, this.Config.CanvasStyles);
      },
      /**
       * @param {string} prop
       * @param {?} value
       * @param {?} type
       * @return {undefined}
       */
      setCanvasStyle : function(prop, value, type) {
        setDataInternal.call(this, "canvas", prop, value, type);
      },
      /**
       * @param {(Array|string)} types
       * @param {Object} obj
       * @return {undefined}
       */
      setCanvasStyles : function(types, obj) {
        types = $.splat(types);
        var attr;
        for (attr in obj) {
          /** @type {number} */
          var i = 0;
          var prevSources = $.splat(obj[attr]);
          var valuesLen = types.length;
          for (;i < valuesLen;i++) {
            this.setCanvasStyle(attr, prevSources[i], types[i]);
          }
        }
      },
      /**
       * @return {undefined}
       */
      removeCanvasStyle : function() {
        removeDataInternal.call(this, "canvas", Array.prototype.slice.call(arguments));
      },
      /**
       * @param {string} property
       * @param {?} type
       * @param {?} force
       * @return {?}
       */
      getLabelData : function(property, type, force) {
        return getDataInternal.call(this, "label", property, type, force, this.Label);
      },
      /**
       * @param {string} prop
       * @param {?} value
       * @param {?} type
       * @return {undefined}
       */
      setLabelData : function(prop, value, type) {
        setDataInternal.call(this, "label", prop, value, type);
      },
      /**
       * @param {(Array|string)} types
       * @param {Object} obj
       * @return {undefined}
       */
      setLabelDataset : function(types, obj) {
        types = $.splat(types);
        var attr;
        for (attr in obj) {
          /** @type {number} */
          var i = 0;
          var prevSources = $.splat(obj[attr]);
          var valuesLen = types.length;
          for (;i < valuesLen;i++) {
            this.setLabelData(attr, prevSources[i], types[i]);
          }
        }
      },
      /**
       * @return {undefined}
       */
      removeLabelData : function() {
        removeDataInternal.call(this, "label", Array.prototype.slice.call(arguments));
      }
    };
  })();
  Graph.Node = new Class({
    /**
     * @param {?} attributes
     * @param {?} klass
     * @param {?} Node
     * @param {?} Edge
     * @param {?} Label
     * @return {undefined}
     */
    initialize : function(attributes, klass, Node, Edge, Label) {
      var innerOptions = {
        id : "",
        name : "",
        data : {},
        startData : {},
        endData : {},
        adjacencies : {},
        selected : false,
        drawn : false,
        exist : false,
        angleSpan : {
          begin : 0,
          end : 0
        },
        pos : new klass,
        startPos : new klass,
        endPos : new klass
      };
      $.extend(this, $.extend(innerOptions, attributes));
      this.Config = this.Node = Node;
      this.Edge = Edge;
      this.Label = Label;
    },
    /**
     * @param {Object} node
     * @return {?}
     */
    adjacentTo : function(node) {
      return node.id in this.adjacencies;
    },
    /**
     * @param {?} id
     * @return {?}
     */
    getAdjacency : function(id) {
      return this.adjacencies[id];
    },
    /**
     * @param {string} expectation
     * @return {?}
     */
    getPos : function(expectation) {
      expectation = expectation || "current";
      if (expectation == "current") {
        return this.pos;
      } else {
        if (expectation == "end") {
          return this.endPos;
        } else {
          if (expectation == "start") {
            return this.startPos;
          }
        }
      }
    },
    /**
     * @param {?} x
     * @param {string} type
     * @return {undefined}
     */
    setPos : function(x, type) {
      type = type || "current";
      var pos;
      if (type == "current") {
        pos = this.pos;
      } else {
        if (type == "end") {
          pos = this.endPos;
        } else {
          if (type == "start") {
            pos = this.startPos;
          }
        }
      }
      pos.set(x);
    }
  });
  Graph.Node.implement(methods);
  Graph.Adjacence = new Class({
    /**
     * @param {number} nodeFrom
     * @param {?} nodeTo
     * @param {Object} data
     * @param {?} Edge
     * @param {number} Label
     * @return {undefined}
     */
    initialize : function(nodeFrom, nodeTo, data, Edge, Label) {
      /** @type {number} */
      this.nodeFrom = nodeFrom;
      this.nodeTo = nodeTo;
      this.data = data || {};
      this.startData = {};
      this.endData = {};
      this.Config = this.Edge = Edge;
      /** @type {number} */
      this.Label = Label;
    }
  });
  Graph.Adjacence.implement(methods);
  Graph.Util = {
    /**
     * @param {string} param
     * @return {?}
     */
    filter : function(param) {
      if (!param || !($.type(param) == "string")) {
        return function() {
          return true;
        };
      }
      var codeSegments = param.split(" ");
      return function(searchParams) {
        /** @type {number} */
        var i = 0;
        for (;i < codeSegments.length;i++) {
          if (searchParams[codeSegments[i]]) {
            return false;
          }
        }
        return true;
      };
    },
    /**
     * @param {?} id
     * @param {?} i
     * @return {?}
     */
    getNode : function(id, i) {
      return id.nodes[i];
    },
    /**
     * @param {Function} graph
     * @param {Function} action
     * @param {string} flags
     * @return {undefined}
     */
    eachNode : function(graph, action, flags) {
      var filter = this.filter(flags);
      var i;
      for (i in graph.nodes) {
        if (filter(graph.nodes[i])) {
          action(graph.nodes[i]);
        }
      }
    },
    /**
     * @param {?} opt_attributes
     * @param {Function} action
     * @param {string} flags
     * @return {undefined}
     */
    each : function(opt_attributes, action, flags) {
      this.eachNode(opt_attributes, action, flags);
    },
    /**
     * @param {Function} node
     * @param {Function} action
     * @param {string} flags
     * @return {undefined}
     */
    eachAdjacency : function(node, action, flags) {
      var adj = node.adjacencies;
      var filter = this.filter(flags);
      var id;
      for (id in adj) {
        var a = adj[id];
        if (filter(a)) {
          if (a.nodeFrom != node) {
            var tmp = a.nodeFrom;
            a.nodeFrom = a.nodeTo;
            a.nodeTo = tmp;
          }
          action(a, id);
        }
      }
    },
    /**
     * @param {?} graph
     * @param {number} recurring
     * @param {number} startDepth
     * @param {string} flags
     * @return {undefined}
     */
    computeLevels : function(graph, recurring, startDepth, flags) {
      startDepth = startDepth || 0;
      var filter = this.filter(flags);
      this.eachNode(graph, function(node) {
        /** @type {boolean} */
        node._flag = false;
        /** @type {number} */
        node._depth = -1;
      }, flags);
      var root = graph.getNode(recurring);
      /** @type {number} */
      root._depth = startDepth;
      /** @type {Array} */
      var queue = [root];
      for (;queue.length != 0;) {
        var node = queue.pop();
        /** @type {boolean} */
        node._flag = true;
        this.eachAdjacency(node, function(adj) {
          var n = adj.nodeTo;
          if (n._flag == false && filter(n)) {
            if (n._depth < 0) {
              n._depth = node._depth + 1 + startDepth;
            }
            queue.unshift(n);
          }
        }, flags);
      }
    },
    /**
     * @param {Element} graph
     * @param {Function} id
     * @param {string} action
     * @param {string} flags
     * @return {undefined}
     */
    eachBFS : function(graph, id, action, flags) {
      var filter = this.filter(flags);
      this.clean(graph);
      /** @type {Array} */
      var lines = [graph.getNode(id)];
      for (;lines.length != 0;) {
        var node = lines.pop();
        /** @type {boolean} */
        node._flag = true;
        action(node, node._depth);
        this.eachAdjacency(node, function(adj) {
          var n = adj.nodeTo;
          if (n._flag == false && filter(n)) {
            /** @type {boolean} */
            n._flag = true;
            lines.unshift(n);
          }
        }, flags);
      }
    },
    /**
     * @param {number} b
     * @param {number} opt_isDefault
     * @param {Object} recurring
     * @param {Function} action
     * @param {string} flags
     * @return {undefined}
     */
    eachLevel : function(b, opt_isDefault, recurring, action, flags) {
      var d = b._depth;
      var filter = this.filter(flags);
      var root = this;
      recurring = recurring === false ? Number.MAX_VALUE - d : recurring;
      (function loopLevel(node, levelBegin, levelEnd) {
        var d = node._depth;
        if (d >= levelBegin && (d <= levelEnd && filter(node))) {
          action(node, d);
        }
        if (d < levelEnd) {
          root.eachAdjacency(node, function(adj) {
            var n = adj.nodeTo;
            if (n._depth > d) {
              loopLevel(n, levelBegin, levelEnd);
            }
          });
        }
      })(b, opt_isDefault + d, recurring + d);
    },
    /**
     * @param {Object} node
     * @param {Function} action
     * @param {string} flags
     * @return {undefined}
     */
    eachSubgraph : function(node, action, flags) {
      this.eachLevel(node, 0, false, action, flags);
    },
    /**
     * @param {Function} node
     * @param {Function} action
     * @param {string} flags
     * @return {undefined}
     */
    eachSubnode : function(node, action, flags) {
      this.eachLevel(node, 1, 1, action, flags);
    },
    /**
     * @param {?} node
     * @param {Object} options
     * @param {string} flags
     * @return {?}
     */
    anySubnode : function(node, options, flags) {
      /** @type {boolean} */
      var flag = false;
      options = options || $.lambda(true);
      var opts = $.type(options) == "string" ? function(deepDataAndEvents) {
        return deepDataAndEvents[options];
      } : options;
      this.eachSubnode(node, function(deepDataAndEvents) {
        if (opts(deepDataAndEvents)) {
          /** @type {boolean} */
          flag = true;
        }
      }, flags);
      return flag;
    },
    /**
     * @param {?} node
     * @param {number} options
     * @param {string} flags
     * @return {?}
     */
    getSubnodes : function(node, options, flags) {
      /** @type {Array} */
      var assigns = [];
      var A = this;
      options = options || 0;
      var isDefault;
      var recurring;
      if ($.type(options) == "array") {
        isDefault = options[0];
        recurring = options[1];
      } else {
        /** @type {number} */
        isDefault = options;
        /** @type {number} */
        recurring = Number.MAX_VALUE - node._depth;
      }
      this.eachLevel(node, isDefault, recurring, function(vvar) {
        assigns.push(vvar);
      }, flags);
      return assigns;
    },
    /**
     * @param {Function} node
     * @return {?}
     */
    getParents : function(node) {
      /** @type {Array} */
      var matched = [];
      this.eachAdjacency(node, function(adj) {
        var n = adj.nodeTo;
        if (n._depth < node._depth) {
          matched.push(n);
        }
      });
      return matched;
    },
    /**
     * @param {?} node
     * @param {?} id
     * @return {?}
     */
    isDescendantOf : function(node, id) {
      if (node.id == id) {
        return true;
      }
      var codeSegments = this.getParents(node);
      /** @type {boolean} */
      var ans = false;
      /** @type {number} */
      var i = 0;
      for (;!ans && i < codeSegments.length;i++) {
        ans = ans || this.isDescendantOf(codeSegments[i], id);
      }
      return ans;
    },
    /**
     * @param {?} graph
     * @return {undefined}
     */
    clean : function(graph) {
      this.eachNode(graph, function(v) {
        /** @type {boolean} */
        v._flag = false;
      });
    },
    /**
     * @param {?} graph
     * @param {string} prop
     * @param {string} flags
     * @return {?}
     */
    getClosestNodeToOrigin : function(graph, prop, flags) {
      return this.getClosestNodeToPos(graph, Transform.KER, prop, flags);
    },
    /**
     * @param {?} graph
     * @param {?} pos
     * @param {string} prop
     * @param {string} flags
     * @return {?}
     */
    getClosestNodeToPos : function(graph, pos, prop, flags) {
      /** @type {null} */
      var node = null;
      prop = prop || "current";
      pos = pos && pos.getc(true) || Vector.KER;
      /**
       * @param {?} a
       * @param {?} b
       * @return {?}
       */
      var distance = function(a, b) {
        /** @type {number} */
        var z0 = a.x - b.x;
        /** @type {number} */
        var z1 = a.y - b.y;
        return z0 * z0 + z1 * z1;
      };
      this.eachNode(graph, function(elem) {
        node = node == null || distance(elem.getPos(prop).getc(true), pos) < distance(node.getPos(prop).getc(true), pos) ? elem : node;
      }, flags);
      return node;
    }
  };
  $.each(["get", "getNode", "each", "eachNode", "computeLevels", "eachBFS", "clean", "getClosestNodeToPos", "getClosestNodeToOrigin"], function(m) {
    /**
     * @return {?}
     */
    Graph.prototype[m] = function() {
      return Graph.Util[m].apply(Graph.Util, [this].concat(Array.prototype.slice.call(arguments)));
    };
  });
  $.each(["eachAdjacency", "eachLevel", "eachSubgraph", "eachSubnode", "anySubnode", "getSubnodes", "getParents", "isDescendantOf"], function(m) {
    /**
     * @return {?}
     */
    Graph.Node.prototype[m] = function() {
      return Graph.Util[m].apply(Graph.Util, [this].concat(Array.prototype.slice.call(arguments)));
    };
  });
  Graph.Op = {
    options : {
      type : "nothing",
      duration : 2E3,
      hideLabels : true,
      fps : 30
    },
    /**
     * @param {?} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.viz = viz;
    },
    /**
     * @param {(Array|string)} node
     * @param {?} opt_attributes
     * @return {undefined}
     */
    removeNode : function(node, opt_attributes) {
      var viz = this.viz;
      var options = $.merge(this.options, viz.controller, opt_attributes);
      var n = $.splat(node);
      var i;
      var element;
      var nodeObj;
      switch(options.type) {
        case "nothing":
          /** @type {number} */
          i = 0;
          for (;i < n.length;i++) {
            viz.graph.removeNode(n[i]);
          }
          break;
        case "replot":
          this.removeNode(n, {
            type : "nothing"
          });
          viz.labels.clearLabels();
          viz.refresh(true);
          break;
        case "fade:seq":
        ;
        case "fade":
          element = this;
          /** @type {number} */
          i = 0;
          for (;i < n.length;i++) {
            nodeObj = viz.graph.getNode(n[i]);
            nodeObj.setData("alpha", 0, "end");
          }
          viz.fx.animate($.merge(options, {
            modes : ["node-property:alpha"],
            /**
             * @return {undefined}
             */
            onComplete : function() {
              element.removeNode(n, {
                type : "nothing"
              });
              viz.labels.clearLabels();
              viz.reposition();
              viz.fx.animate($.merge(options, {
                modes : ["linear"]
              }));
            }
          }));
          break;
        case "fade:con":
          element = this;
          /** @type {number} */
          i = 0;
          for (;i < n.length;i++) {
            nodeObj = viz.graph.getNode(n[i]);
            nodeObj.setData("alpha", 0, "end");
            /** @type {boolean} */
            nodeObj.ignore = true;
          }
          viz.reposition();
          viz.fx.animate($.merge(options, {
            modes : ["node-property:alpha", "linear"],
            /**
             * @return {undefined}
             */
            onComplete : function() {
              element.removeNode(n, {
                type : "nothing"
              });
              if (options.onComplete) {
                options.onComplete();
              }
            }
          }));
          break;
        case "iter":
          element = this;
          viz.fx.sequence({
            /**
             * @return {?}
             */
            condition : function() {
              return n.length != 0;
            },
            /**
             * @return {undefined}
             */
            step : function() {
              element.removeNode(n.shift(), {
                type : "nothing"
              });
              viz.labels.clearLabels();
            },
            /**
             * @return {undefined}
             */
            onComplete : function() {
              if (options.onComplete) {
                options.onComplete();
              }
            },
            duration : Math.ceil(options.duration / n.length)
          });
          break;
        default:
          this.doError();
      }
    },
    /**
     * @param {?} vertex
     * @param {?} opt_attributes
     * @return {undefined}
     */
    removeEdge : function(vertex, opt_attributes) {
      var viz = this.viz;
      var options = $.merge(this.options, viz.controller, opt_attributes);
      var v = $.type(vertex[0]) == "string" ? [vertex] : vertex;
      var ii;
      var that;
      var nodeObj;
      switch(options.type) {
        case "nothing":
          /** @type {number} */
          ii = 0;
          for (;ii < v.length;ii++) {
            viz.graph.removeAdjacence(v[ii][0], v[ii][1]);
          }
          break;
        case "replot":
          this.removeEdge(v, {
            type : "nothing"
          });
          viz.refresh(true);
          break;
        case "fade:seq":
        ;
        case "fade":
          that = this;
          /** @type {number} */
          ii = 0;
          for (;ii < v.length;ii++) {
            nodeObj = viz.graph.getAdjacence(v[ii][0], v[ii][1]);
            if (nodeObj) {
              nodeObj.setData("alpha", 0, "end");
            }
          }
          viz.fx.animate($.merge(options, {
            modes : ["edge-property:alpha"],
            /**
             * @return {undefined}
             */
            onComplete : function() {
              that.removeEdge(v, {
                type : "nothing"
              });
              viz.reposition();
              viz.fx.animate($.merge(options, {
                modes : ["linear"]
              }));
            }
          }));
          break;
        case "fade:con":
          that = this;
          /** @type {number} */
          ii = 0;
          for (;ii < v.length;ii++) {
            nodeObj = viz.graph.getAdjacence(v[ii][0], v[ii][1]);
            if (nodeObj) {
              nodeObj.setData("alpha", 0, "end");
              /** @type {boolean} */
              nodeObj.ignore = true;
            }
          }
          viz.reposition();
          viz.fx.animate($.merge(options, {
            modes : ["edge-property:alpha", "linear"],
            /**
             * @return {undefined}
             */
            onComplete : function() {
              that.removeEdge(v, {
                type : "nothing"
              });
              if (options.onComplete) {
                options.onComplete();
              }
            }
          }));
          break;
        case "iter":
          that = this;
          viz.fx.sequence({
            /**
             * @return {?}
             */
            condition : function() {
              return v.length != 0;
            },
            /**
             * @return {undefined}
             */
            step : function() {
              that.removeEdge(v.shift(), {
                type : "nothing"
              });
              viz.labels.clearLabels();
            },
            /**
             * @return {undefined}
             */
            onComplete : function() {
              options.onComplete();
            },
            duration : Math.ceil(options.duration / v.length)
          });
          break;
        default:
          this.doError();
      }
    },
    /**
     * @param {?} json
     * @param {?} opt
     * @return {undefined}
     */
    sum : function(json, opt) {
      var viz = this.viz;
      var options = $.merge(this.options, viz.controller, opt);
      var root = viz.root;
      var graph;
      viz.root = opt.id || viz.root;
      switch(options.type) {
        case "nothing":
          graph = viz.construct(json);
          graph.eachNode(function(rt) {
            rt.eachAdjacency(function(adj) {
              viz.graph.addAdjacence(adj.nodeFrom, adj.nodeTo, adj.data);
            });
          });
          break;
        case "replot":
          viz.refresh(true);
          this.sum(json, {
            type : "nothing"
          });
          viz.refresh(true);
          break;
        case "fade:seq":
        ;
        case "fade":
        ;
        case "fade:con":
          that = this;
          graph = viz.construct(json);
          var fadeEdges = this.preprocessSum(graph);
          /** @type {Array} */
          var modes = !fadeEdges ? ["node-property:alpha"] : ["node-property:alpha", "edge-property:alpha"];
          viz.reposition();
          if (options.type != "fade:con") {
            viz.fx.animate($.merge(options, {
              modes : ["linear"],
              /**
               * @return {undefined}
               */
              onComplete : function() {
                viz.fx.animate($.merge(options, {
                  modes : modes,
                  /**
                   * @return {undefined}
                   */
                  onComplete : function() {
                    options.onComplete();
                  }
                }));
              }
            }));
          } else {
            viz.graph.eachNode(function(elem) {
              if (elem.id != root && elem.pos.isZero()) {
                elem.pos.set(elem.endPos);
                elem.startPos.set(elem.endPos);
              }
            });
            viz.fx.animate($.merge(options, {
              modes : ["linear"].concat(modes)
            }));
          }
          break;
        default:
          this.doError();
      }
    },
    /**
     * @param {(Error|string)} json
     * @param {Element} opt
     * @param {Object} extraModes
     * @return {undefined}
     */
    morph : function(json, opt, extraModes) {
      extraModes = extraModes || {};
      var viz = this.viz;
      var options = $.merge(this.options, viz.controller, opt);
      var root = viz.root;
      var graph;
      viz.root = opt.id || viz.root;
      switch(options.type) {
        case "nothing":
          graph = viz.construct(json);
          graph.eachNode(function(elem) {
            var H = viz.graph.hasNode(elem.id);
            elem.eachAdjacency(function(adj) {
              /** @type {boolean} */
              var L = !!viz.graph.getAdjacence(adj.nodeFrom.id, adj.nodeTo.id);
              viz.graph.addAdjacence(adj.nodeFrom, adj.nodeTo, adj.data);
              if (L) {
                var event = viz.graph.getAdjacence(adj.nodeFrom.id, adj.nodeTo.id);
                var prop;
                for (prop in adj.data || {}) {
                  event.data[prop] = adj.data[prop];
                }
              }
            });
            if (H) {
              var jQuery = viz.graph.getNode(elem.id);
              var name;
              for (name in elem.data || {}) {
                jQuery.data[name] = elem.data[name];
              }
            }
          });
          viz.graph.eachNode(function(elem) {
            elem.eachAdjacency(function(adj) {
              if (!graph.getAdjacence(adj.nodeFrom.id, adj.nodeTo.id)) {
                viz.graph.removeAdjacence(adj.nodeFrom.id, adj.nodeTo.id);
              }
            });
            if (!graph.hasNode(elem.id)) {
              viz.graph.removeNode(elem.id);
            }
          });
          break;
        case "replot":
          viz.labels.clearLabels(true);
          this.morph(json, {
            type : "nothing"
          });
          viz.refresh(true);
          viz.refresh(true);
          break;
        case "fade:seq":
        ;
        case "fade":
        ;
        case "fade:con":
          that = this;
          graph = viz.construct(json);
          var selection = "node-property" in extraModes && $.map($.splat(extraModes["node-property"]), function(type) {
            return "$" + type;
          });
          viz.graph.eachNode(function(elem) {
            var response = graph.getNode(elem.id);
            if (!response) {
              elem.setData("alpha", 1);
              elem.setData("alpha", 1, "start");
              elem.setData("alpha", 0, "end");
              /** @type {boolean} */
              elem.ignore = true;
            } else {
              var template = response.data;
              var prop;
              for (prop in template) {
                if (selection && $.indexOf(selection, prop) > -1) {
                  elem.endData[prop] = template[prop];
                } else {
                  elem.data[prop] = template[prop];
                }
              }
            }
          });
          viz.graph.eachNode(function(node) {
            if (node.ignore) {
              return;
            }
            node.eachAdjacency(function(adj) {
              if (adj.nodeFrom.ignore || adj.nodeTo.ignore) {
                return;
              }
              var nodeFrom = graph.getNode(adj.nodeFrom.id);
              var nodeTo = graph.getNode(adj.nodeTo.id);
              if (!nodeFrom.adjacentTo(nodeTo)) {
                adj = viz.graph.getAdjacence(nodeFrom.id, nodeTo.id);
                /** @type {boolean} */
                fadeEdges = true;
                adj.setData("alpha", 1);
                adj.setData("alpha", 1, "start");
                adj.setData("alpha", 0, "end");
              }
            });
          });
          var fadeEdges = this.preprocessSum(graph);
          /** @type {Array} */
          var modes = !fadeEdges ? ["node-property:alpha"] : ["node-property:alpha", "edge-property:alpha"];
          modes[0] = modes[0] + ("node-property" in extraModes ? ":" + $.splat(extraModes["node-property"]).join(":") : "");
          modes[1] = (modes[1] || "edge-property:alpha") + ("edge-property" in extraModes ? ":" + $.splat(extraModes["edge-property"]).join(":") : "");
          if ("label-property" in extraModes) {
            modes.push("label-property:" + $.splat(extraModes["label-property"]).join(":"));
          }
          if (viz.reposition) {
            viz.reposition();
          } else {
            viz.compute("end");
          }
          viz.graph.eachNode(function(elem) {
            if (elem.id != root && elem.pos.getp().equals(Transform.KER)) {
              elem.pos.set(elem.endPos);
              elem.startPos.set(elem.endPos);
            }
          });
          viz.fx.animate($.merge(options, {
            modes : [extraModes.position || "polar"].concat(modes),
            /**
             * @return {undefined}
             */
            onComplete : function() {
              viz.graph.eachNode(function(elem) {
                if (elem.ignore) {
                  viz.graph.removeNode(elem.id);
                }
              });
              viz.graph.eachNode(function(rt) {
                rt.eachAdjacency(function(adj) {
                  if (adj.ignore) {
                    viz.graph.removeAdjacence(adj.nodeFrom.id, adj.nodeTo.id);
                  }
                });
              });
              options.onComplete();
            }
          }));
          break;
        default:
        ;
      }
    },
    /**
     * @param {?} node
     * @param {Object} opt
     * @return {undefined}
     */
    contract : function(node, opt) {
      var viz = this.viz;
      if (node.collapsed || !node.anySubnode($.lambda(true))) {
        return;
      }
      opt = $.merge(this.options, viz.config, opt || {}, {
        modes : ["node-property:alpha:span", "linear"]
      });
      /** @type {boolean} */
      node.collapsed = true;
      (function subn(n) {
        n.eachSubnode(function(ch) {
          /** @type {boolean} */
          ch.ignore = true;
          ch.setData("alpha", 0, opt.type == "animate" ? "end" : "current");
          subn(ch);
        });
      })(node);
      if (opt.type == "animate") {
        viz.compute("end");
        if (viz.rotated) {
          viz.rotate(viz.rotated, "none", {
            property : "end"
          });
        }
        (function subn(n) {
          n.eachSubnode(function(ch) {
            ch.setPos(node.getPos("end"), "end");
            subn(ch);
          });
        })(node);
        viz.fx.animate(opt);
      } else {
        if (opt.type == "replot") {
          viz.refresh();
        }
      }
    },
    /**
     * @param {Object} node
     * @param {Object} opt
     * @return {undefined}
     */
    expand : function(node, opt) {
      if (!("collapsed" in node)) {
        return;
      }
      var viz = this.viz;
      opt = $.merge(this.options, viz.config, opt || {}, {
        modes : ["node-property:alpha:span", "linear"]
      });
      delete node.collapsed;
      (function subn(n) {
        n.eachSubnode(function(ch) {
          delete ch.ignore;
          ch.setData("alpha", 1, opt.type == "animate" ? "end" : "current");
          subn(ch);
        });
      })(node);
      if (opt.type == "animate") {
        viz.compute("end");
        if (viz.rotated) {
          viz.rotate(viz.rotated, "none", {
            property : "end"
          });
        }
        viz.fx.animate(opt);
      } else {
        if (opt.type == "replot") {
          viz.refresh();
        }
      }
    },
    /**
     * @param {?} graph
     * @return {?}
     */
    preprocessSum : function(graph) {
      var viz = this.viz;
      graph.eachNode(function(elem) {
        if (!viz.graph.hasNode(elem.id)) {
          viz.graph.addNode(elem);
          var n = viz.graph.getNode(elem.id);
          n.setData("alpha", 0);
          n.setData("alpha", 0, "start");
          n.setData("alpha", 1, "end");
        }
      });
      /** @type {boolean} */
      var fadeEdges = false;
      graph.eachNode(function(rt) {
        rt.eachAdjacency(function(adj) {
          var nodeFrom = viz.graph.getNode(adj.nodeFrom.id);
          var nodeTo = viz.graph.getNode(adj.nodeTo.id);
          if (!nodeFrom.adjacentTo(nodeTo)) {
            adj = viz.graph.addAdjacence(nodeFrom, nodeTo, adj.data);
            if (nodeFrom.startAlpha == nodeFrom.endAlpha && nodeTo.startAlpha == nodeTo.endAlpha) {
              /** @type {boolean} */
              fadeEdges = true;
              adj.setData("alpha", 0);
              adj.setData("alpha", 0, "start");
              adj.setData("alpha", 1, "end");
            }
          }
        });
      });
      return fadeEdges;
    }
  };
  var self = {
    none : {
      /** @type {function (): undefined} */
      render : $.empty,
      contains : $.lambda(false)
    },
    circle : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @param {?} type
       * @return {undefined}
       */
      render : function(adj, lab, event, type) {
        var that = type.getCtx();
        that.beginPath();
        that.arc(lab.x, lab.y, event, 0, Math.PI * 2, true);
        that.closePath();
        that[adj]();
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @param {?} testName
       * @return {?}
       */
      contains : function(opt_attributes, value, testName) {
        /** @type {number} */
        var z0 = opt_attributes.x - value.x;
        /** @type {number} */
        var z1 = opt_attributes.y - value.y;
        /** @type {number} */
        var z = z0 * z0 + z1 * z1;
        return z <= testName * testName;
      }
    },
    ellipse : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @param {?} type
       * @param {?} keepData
       * @return {undefined}
       */
      render : function(adj, lab, event, type, keepData) {
        var ctx = keepData.getCtx();
        /** @type {number} */
        var c = 1;
        /** @type {number} */
        var scaleY = 1;
        /** @type {number} */
        var scaleposx = 1;
        /** @type {number} */
        var scaleposy = 1;
        /** @type {number} */
        var diameter = 0;
        if (event > type) {
          /** @type {number} */
          diameter = event / 2;
          /** @type {number} */
          scaleY = type / event;
          /** @type {number} */
          scaleposy = event / type;
        } else {
          /** @type {number} */
          diameter = type / 2;
          /** @type {number} */
          c = event / type;
          /** @type {number} */
          scaleposx = type / event;
        }
        ctx.save();
        ctx.scale(c, scaleY);
        ctx.beginPath();
        ctx.arc(lab.x * scaleposx, lab.y * scaleposy, diameter, 0, Math.PI * 2, true);
        ctx.closePath();
        ctx[adj]();
        ctx.restore();
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @param {?} testName
       * @param {?} epsilon
       * @return {?}
       */
      contains : function(opt_attributes, value, testName, epsilon) {
        /** @type {number} */
        var radii = 0;
        /** @type {number} */
        var B = 1;
        /** @type {number} */
        var t = 1;
        /** @type {number} */
        var z0 = 0;
        /** @type {number} */
        var z1 = 0;
        /** @type {number} */
        var distSq = 0;
        if (testName > epsilon) {
          /** @type {number} */
          radii = testName / 2;
          /** @type {number} */
          t = epsilon / testName;
        } else {
          /** @type {number} */
          radii = epsilon / 2;
          /** @type {number} */
          B = testName / epsilon;
        }
        /** @type {number} */
        z0 = (opt_attributes.x - value.x) * (1 / B);
        /** @type {number} */
        z1 = (opt_attributes.y - value.y) * (1 / t);
        /** @type {number} */
        distSq = z0 * z0 + z1 * z1;
        return distSq <= radii * radii;
      }
    },
    square : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @param {?} type
       * @return {undefined}
       */
      render : function(adj, lab, event, type) {
        type.getCtx()[adj + "Rect"](lab.x - event, lab.y - event, 2 * event, 2 * event);
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @param {?} testName
       * @return {?}
       */
      contains : function(opt_attributes, value, testName) {
        return Math.abs(value.x - opt_attributes.x) <= testName && Math.abs(value.y - opt_attributes.y) <= testName;
      }
    },
    rectangle : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @param {?} type
       * @param {?} keepData
       * @return {undefined}
       */
      render : function(adj, lab, event, type, keepData) {
        keepData.getCtx()[adj + "Rect"](lab.x - event / 2, lab.y - type / 2, event, type);
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @param {?} testName
       * @param {?} epsilon
       * @return {?}
       */
      contains : function(opt_attributes, value, testName, epsilon) {
        return Math.abs(value.x - opt_attributes.x) <= testName / 2 && Math.abs(value.y - opt_attributes.y) <= epsilon / 2;
      }
    },
    triangle : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @param {?} type
       * @return {undefined}
       */
      render : function(adj, lab, event, type) {
        var context = type.getCtx();
        var left = lab.x;
        /** @type {number} */
        var fromY = lab.y - event;
        /** @type {number} */
        var vLine2 = left - event;
        var hly = lab.y + event;
        var centerX = left + event;
        var gy = hly;
        context.beginPath();
        context.moveTo(left, fromY);
        context.lineTo(vLine2, hly);
        context.lineTo(centerX, gy);
        context.closePath();
        context[adj]();
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @param {?} testName
       * @return {?}
       */
      contains : function(opt_attributes, value, testName) {
        return self.circle.contains(opt_attributes, value, testName);
      }
    },
    star : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @param {?} type
       * @return {undefined}
       */
      render : function(adj, lab, event, type) {
        var ctx = type.getCtx();
        /** @type {number} */
        var thetap = Math.PI / 5;
        ctx.save();
        ctx.translate(lab.x, lab.y);
        ctx.beginPath();
        ctx.moveTo(event, 0);
        /** @type {number} */
        var y = 0;
        for (;y < 9;y++) {
          ctx.rotate(thetap);
          if (y % 2 == 0) {
            ctx.lineTo(event / 0.525731 * 0.200811, 0);
          } else {
            ctx.lineTo(event, 0);
          }
        }
        ctx.closePath();
        ctx[adj]();
        ctx.restore();
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @param {?} testName
       * @return {?}
       */
      contains : function(opt_attributes, value, testName) {
        return self.circle.contains(opt_attributes, value, testName);
      }
    }
  };
  var element = {
    line : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @return {undefined}
       */
      render : function(adj, lab, event) {
        var ctx = event.getCtx();
        ctx.beginPath();
        ctx.moveTo(adj.x, adj.y);
        ctx.lineTo(lab.x, lab.y);
        ctx.stroke();
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @param {?} testName
       * @param {?} epsilon
       * @return {?}
       */
      contains : function(opt_attributes, value, testName, epsilon) {
        /** @type {function (...[*]): number} */
        var min = Math.min;
        /** @type {function (...[*]): number} */
        var max = Math.max;
        /** @type {number} */
        var minX = min(opt_attributes.x, value.x);
        /** @type {number} */
        var x = max(opt_attributes.x, value.x);
        /** @type {number} */
        var minY = min(opt_attributes.y, value.y);
        /** @type {number} */
        var maxY = max(opt_attributes.y, value.y);
        if (testName.x >= minX && (testName.x <= x && (testName.y >= minY && testName.y <= maxY))) {
          if (Math.abs(value.x - opt_attributes.x) <= epsilon) {
            return true;
          }
          var newTop = (value.y - opt_attributes.y) / (value.x - opt_attributes.x) * (testName.x - opt_attributes.x) + opt_attributes.y;
          return Math.abs(newTop - testName.y) <= epsilon;
        }
        return false;
      }
    },
    arrow : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @param {?} type
       * @param {?} keepData
       * @return {undefined}
       */
      render : function(adj, lab, event, type, keepData) {
        var ctx = keepData.getCtx();
        if (type) {
          var fx = adj;
          adj = lab;
          lab = fx;
        }
        var p = new Vector(lab.x - adj.x, lab.y - adj.y);
        p.$scale(event / p.norm());
        var collection = new Vector(lab.x - p.x, lab.y - p.y);
        var to = new Vector(-p.y / 2, p.x / 2);
        var d = collection.add(to);
        var p4coord = collection.$add(to.$scale(-1));
        ctx.beginPath();
        ctx.moveTo(adj.x, adj.y);
        ctx.lineTo(lab.x, lab.y);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(d.x, d.y);
        ctx.lineTo(p4coord.x, p4coord.y);
        ctx.lineTo(lab.x, lab.y);
        ctx.closePath();
        ctx.fill();
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @param {?} testName
       * @param {?} epsilon
       * @return {?}
       */
      contains : function(opt_attributes, value, testName, epsilon) {
        return element.line.contains(opt_attributes, value, testName, epsilon);
      }
    },
    hyperline : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @param {?} type
       * @return {undefined}
       */
      render : function(adj, lab, event, type) {
        /**
         * @param {?} p1
         * @param {?} p2
         * @return {?}
         */
        function computeArcThroughTwoPoints(p1, p2) {
          /** @type {number} */
          var YY_START = p1.x * p2.y - p1.y * p2.x;
          /** @type {number} */
          var YYSTATE = YY_START;
          var b3 = p1.squaredNorm();
          var b1 = p2.squaredNorm();
          if (YY_START == 0) {
            return{
              x : 0,
              y : 0,
              ratio : -1
            };
          }
          /** @type {number} */
          var z0 = (p1.y * b1 - p2.y * b3 + p1.y - p2.y) / YY_START;
          /** @type {number} */
          var z1 = (p2.x * b3 - p1.x * b1 + p2.x - p1.x) / YYSTATE;
          /** @type {number} */
          var moveX = -z0 / 2;
          /** @type {number} */
          var moveY = -z1 / 2;
          /** @type {number} */
          var squaredRatio = (z0 * z0 + z1 * z1) / 4 - 1;
          if (squaredRatio < 0) {
            return{
              x : 0,
              y : 0,
              ratio : -1
            };
          }
          /** @type {number} */
          var ratio = Math.sqrt(squaredRatio);
          var out = {
            x : moveX,
            y : moveY,
            ratio : ratio > 1E3 ? -1 : ratio,
            a : z0,
            b : z1
          };
          return out;
        }
        /**
         * @param {number} angleBegin
         * @param {number} angleEnd
         * @return {?}
         */
        function sense(angleBegin, angleEnd) {
          return angleBegin < angleEnd ? angleBegin + Math.PI > angleEnd ? false : true : angleEnd + Math.PI > angleBegin ? true : false;
        }
        var ctx = type.getCtx();
        var centerOfCircle = computeArcThroughTwoPoints(adj, lab);
        if (centerOfCircle.a > 1E3 || (centerOfCircle.b > 1E3 || centerOfCircle.ratio < 0)) {
          ctx.beginPath();
          ctx.moveTo(adj.x * event, adj.y * event);
          ctx.lineTo(lab.x * event, lab.y * event);
          ctx.stroke();
        } else {
          /** @type {number} */
          var angleBegin = Math.atan2(lab.y - centerOfCircle.y, lab.x - centerOfCircle.x);
          /** @type {number} */
          var angleEnd = Math.atan2(adj.y - centerOfCircle.y, adj.x - centerOfCircle.x);
          sense = sense(angleBegin, angleEnd);
          ctx.beginPath();
          ctx.arc(centerOfCircle.x * event, centerOfCircle.y * event, centerOfCircle.ratio * event, angleBegin, angleEnd, sense);
          ctx.stroke();
        }
      },
      contains : $.lambda(false)
    }
  };
  Graph.Plot = {
    /**
     * @param {Object} viz
     * @param {?} klass
     * @return {undefined}
     */
    initialize : function(viz, klass) {
      /** @type {Object} */
      this.viz = viz;
      this.config = viz.config;
      this.node = viz.config.Node;
      this.edge = viz.config.Edge;
      this.animation = new Animation;
      this.nodeTypes = new klass.Plot.NodeTypes;
      this.edgeTypes = new klass.Plot.EdgeTypes;
      this.labels = viz.labels;
    },
    nodeHelper : self,
    edgeHelper : element,
    Interpolator : {
      map : {
        border : "color",
        color : "color",
        width : "number",
        height : "number",
        dim : "number",
        alpha : "number",
        lineWidth : "number",
        angularWidth : "number",
        span : "number",
        valueArray : "array-number",
        dimArray : "array-number"
      },
      canvas : {
        globalAlpha : "number",
        fillStyle : "color",
        strokeStyle : "color",
        lineWidth : "number",
        shadowBlur : "number",
        shadowColor : "color",
        shadowOffsetX : "number",
        shadowOffsetY : "number",
        miterLimit : "number"
      },
      label : {
        size : "number",
        color : "color"
      },
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @return {?}
       */
      compute : function(adj, lab, event) {
        return adj + (lab - adj) * event;
      },
      /**
       * @param {Object} elem
       * @param {?} dataAndEvents
       * @param {?} delta
       * @param {Object} vector
       * @return {undefined}
       */
      moebius : function(elem, dataAndEvents, delta, vector) {
        var v = vector.scale(-delta);
        if (v.norm() < 1) {
          var x = v.x;
          var y = v.y;
          var pos = elem.startPos.getc().moebiusTransformation(v);
          elem.pos.setc(pos.x, pos.y);
          v.x = x;
          v.y = y;
        }
      },
      /**
       * @param {Object} n
       * @param {?} diff
       * @param {?} qualifier
       * @return {undefined}
       */
      linear : function(n, diff, qualifier) {
        var from = n.startPos.getc(true);
        var to = n.endPos.getc(true);
        n.pos.setc(this.compute(from.x, to.x, qualifier), this.compute(from.y, to.y, qualifier));
      },
      /**
       * @param {Object} elem
       * @param {?} r
       * @param {number} delta
       * @return {undefined}
       */
      polar : function(elem, r, delta) {
        var from = elem.startPos.getp(true);
        var to = elem.endPos.getp();
        var ans = to.interpolate(from, delta);
        elem.pos.setp(ans.theta, ans.rho);
      },
      /**
       * @param {Array} elem
       * @param {?} prop
       * @param {?} qualifier
       * @param {number} getter
       * @param {number} setter
       * @return {undefined}
       */
      number : function(elem, prop, qualifier, getter, setter) {
        var from = elem[getter](prop, "start");
        var lab = elem[getter](prop, "end");
        elem[setter](prop, this.compute(from, lab, qualifier));
      },
      /**
       * @param {Array} elem
       * @param {?} prop
       * @param {?} qualifier
       * @param {number} getter
       * @param {number} setter
       * @return {undefined}
       */
      color : function(elem, prop, qualifier, getter, setter) {
        var arr = $.hexToRgb(elem[getter](prop, "start"));
        var to = $.hexToRgb(elem[getter](prop, "end"));
        var comp = this.compute;
        var val = $.rgbToHex([parseInt(comp(arr[0], to[0], qualifier)), parseInt(comp(arr[1], to[1], qualifier)), parseInt(comp(arr[2], to[2], qualifier))]);
        elem[setter](prop, val);
      },
      /**
       * @param {Array} elem
       * @param {?} prop
       * @param {?} qualifier
       * @param {number} getter
       * @param {number} setter
       * @return {undefined}
       */
      "array-number" : function(elem, prop, qualifier, getter, setter) {
        var v = elem[getter](prop, "start");
        var parts = elem[getter](prop, "end");
        /** @type {Array} */
        var cur = [];
        /** @type {number} */
        var id = 0;
        var pad = v.length;
        for (;id < pad;id++) {
          var from = v[id];
          var lab = parts[id];
          if (from.length) {
            /** @type {number} */
            var i = 0;
            var len = from.length;
            /** @type {Array} */
            var curi = [];
            for (;i < len;i++) {
              curi.push(this.compute(from[i], lab[i], qualifier));
            }
            cur.push(curi);
          } else {
            cur.push(this.compute(from, lab, qualifier));
          }
        }
        elem[setter](prop, cur);
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @param {?} testName
       * @param {?} epsilon
       * @param {?} node
       * @param {?} namespaces
       * @return {undefined}
       */
      node : function(opt_attributes, value, testName, epsilon, node, namespaces) {
        epsilon = this[epsilon];
        if (value) {
          var len = value.length;
          /** @type {number} */
          var status = 0;
          for (;status < len;status++) {
            var msg = value[status];
            this[epsilon[msg]](opt_attributes, msg, testName, node, namespaces);
          }
        } else {
          for (msg in epsilon) {
            this[epsilon[msg]](opt_attributes, msg, testName, node, namespaces);
          }
        }
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @param {?} testName
       * @param {?} epsilon
       * @param {?} getter
       * @param {?} setter
       * @return {undefined}
       */
      edge : function(opt_attributes, value, testName, epsilon, getter, setter) {
        var adjs = opt_attributes.adjacencies;
        var id;
        for (id in adjs) {
          this["node"](adjs[id], value, testName, epsilon, getter, setter);
        }
      },
      /**
       * @param {?} elem
       * @param {?} props
       * @param {?} delta
       * @return {undefined}
       */
      "node-property" : function(elem, props, delta) {
        this["node"](elem, props, delta, "map", "getData", "setData");
      },
      /**
       * @param {?} elem
       * @param {?} props
       * @param {?} delta
       * @return {undefined}
       */
      "edge-property" : function(elem, props, delta) {
        this["edge"](elem, props, delta, "map", "getData", "setData");
      },
      /**
       * @param {?} elem
       * @param {?} props
       * @param {?} delta
       * @return {undefined}
       */
      "label-property" : function(elem, props, delta) {
        this["node"](elem, props, delta, "label", "getLabelData", "setLabelData");
      },
      /**
       * @param {?} elem
       * @param {?} props
       * @param {?} delta
       * @return {undefined}
       */
      "node-style" : function(elem, props, delta) {
        this["node"](elem, props, delta, "canvas", "getCanvasStyle", "setCanvasStyle");
      },
      /**
       * @param {?} elem
       * @param {?} props
       * @param {?} delta
       * @return {undefined}
       */
      "edge-style" : function(elem, props, delta) {
        this["edge"](elem, props, delta, "canvas", "getCanvasStyle", "setCanvasStyle");
      }
    },
    /**
     * @param {Object} options
     * @return {undefined}
     */
    sequence : function(options) {
      var that = this;
      options = $.merge({
        condition : $.lambda(false),
        /** @type {function (): undefined} */
        step : $.empty,
        /** @type {function (): undefined} */
        onComplete : $.empty,
        duration : 200
      }, options || {});
      /** @type {number} */
      var poll = setInterval(function() {
        if (options.condition()) {
          options.step();
        } else {
          clearInterval(poll);
          options.onComplete();
        }
        that.viz.refresh(true);
      }, options.duration);
    },
    /**
     * @param {Object} obj
     * @return {?}
     */
    prepare : function(obj) {
      var graph = this.viz.graph;
      var accessors = {
        "node-property" : {
          getter : "getData",
          setter : "setData"
        },
        "edge-property" : {
          getter : "getData",
          setter : "setData"
        },
        "node-style" : {
          getter : "getCanvasStyle",
          setter : "setCanvasStyle"
        },
        "edge-style" : {
          getter : "getCanvasStyle",
          setter : "setCanvasStyle"
        }
      };
      var self = {};
      if ($.type(obj) == "array") {
        /** @type {number} */
        var i = 0;
        var l = obj.length;
        for (;i < l;i++) {
          var e = obj[i].split(":");
          self[e.shift()] = e;
        }
      } else {
        var p;
        for (p in obj) {
          if (p == "position") {
            /** @type {Array} */
            self[obj.position] = [];
          } else {
            self[p] = $.splat(obj[p]);
          }
        }
      }
      graph.eachNode(function(node) {
        node.startPos.set(node.pos);
        $.each(["node-property", "node-style"], function(name) {
          if (name in self) {
            var events = self[name];
            /** @type {number} */
            var i = 0;
            var l = events.length;
            for (;i < l;i++) {
              node[accessors[name].setter](events[i], node[accessors[name].getter](events[i]), "start");
            }
          }
        });
        $.each(["edge-property", "edge-style"], function(name) {
          if (name in self) {
            var events = self[name];
            node.eachAdjacency(function(adj) {
              /** @type {number} */
              var i = 0;
              var l = events.length;
              for (;i < l;i++) {
                adj[accessors[name].setter](events[i], adj[accessors[name].getter](events[i]), "start");
              }
            });
          }
        });
      });
      return self;
    },
    /**
     * @param {?} opt
     * @param {?} versor
     * @return {undefined}
     */
    animate : function(opt, versor) {
      opt = $.merge(this.viz.config, opt || {});
      var that = this;
      var viz = this.viz;
      var graph = viz.graph;
      var interp = this.Interpolator;
      var animation = opt.type === "nodefx" ? this.nodeFxAnimation : this.animation;
      var m = this.prepare(opt.modes);
      if (opt.hideLabels) {
        this.labels.hideLabels(true);
      }
      animation.setOptions($.extend(opt, {
        $animating : false,
        /**
         * @param {?} adj
         * @return {undefined}
         */
        compute : function(adj) {
          graph.eachNode(function(node) {
            var p;
            for (p in m) {
              interp[p](node, m[p], adj, versor);
            }
          });
          that.plot(opt, this.$animating, adj);
          /** @type {boolean} */
          this.$animating = true;
        },
        /**
         * @return {undefined}
         */
        complete : function() {
          if (opt.hideLabels) {
            that.labels.hideLabels(false);
          }
          that.plot(opt);
          opt.onComplete();
        }
      })).start();
    },
    /**
     * @param {Object} opt
     * @return {undefined}
     */
    nodeFx : function(opt) {
      var viz = this.viz;
      var graph = viz.graph;
      var animation = this.nodeFxAnimation;
      var nodes = $.merge(this.viz.config, {
        elements : {
          id : false,
          properties : {}
        },
        reposition : false
      });
      opt = $.merge(nodes, opt || {}, {
        /** @type {function (): undefined} */
        onBeforeCompute : $.empty,
        /** @type {function (): undefined} */
        onAfterCompute : $.empty
      });
      animation.stopTimer();
      var props = opt.elements.properties;
      if (!opt.elements.id) {
        graph.eachNode(function(n) {
          var prop;
          for (prop in props) {
            n.setData(prop, props[prop], "end");
          }
        });
      } else {
        var attributes = $.splat(opt.elements.id);
        $.each(attributes, function(node) {
          var n = graph.getNode(node);
          if (n) {
            var prop;
            for (prop in props) {
              n.setData(prop, props[prop], "end");
            }
          }
        });
      }
      /** @type {Array} */
      var assigns = [];
      var vvar;
      for (vvar in props) {
        assigns.push(vvar);
      }
      /** @type {Array} */
      var modes = ["node-property:" + assigns.join(":")];
      if (opt.reposition) {
        modes.push("linear");
        viz.compute("end");
      }
      this.animate($.merge(opt, {
        modes : modes,
        type : "nodefx"
      }));
    },
    /**
     * @param {?} opt
     * @param {boolean} animating
     * @return {undefined}
     */
    plot : function(opt, animating) {
      var viz = this.viz;
      var graph = viz.graph;
      var canvas = viz.canvas;
      var id = viz.root;
      var that = this;
      var F = canvas.getCtx();
      /** @type {function (...[*]): number} */
      var min = Math.min;
      opt = opt || this.viz.controller;
      if (opt.clearCanvas) {
        canvas.clear();
      }
      var n = graph.getNode(id);
      if (!n) {
        return;
      }
      /** @type {boolean} */
      var T = !!n.visited;
      graph.eachNode(function(from) {
        var nodeAlpha = from.getData("alpha");
        from.eachAdjacency(function(adj) {
          var nodeTo = adj.nodeTo;
          if (!!nodeTo.visited === T && (from.drawn && nodeTo.drawn)) {
            if (!animating) {
              opt.onBeforePlotLine(adj);
            }
            that.plotLine(adj, canvas, animating);
            if (!animating) {
              opt.onAfterPlotLine(adj);
            }
          }
        });
        if (from.drawn) {
          if (!animating) {
            opt.onBeforePlotNode(from);
          }
          that.plotNode(from, canvas, animating);
          if (!animating) {
            opt.onAfterPlotNode(from);
          }
        }
        if (!that.labelsHidden && opt.withLabels) {
          if (from.drawn && nodeAlpha >= 0.95) {
            that.labels.plotLabel(canvas, from, opt);
          } else {
            that.labels.hideLabel(from, false);
          }
        }
        /** @type {boolean} */
        from.visited = !T;
      });
    },
    /**
     * @param {?} npos
     * @param {?} opt
     * @param {boolean} animating
     * @return {undefined}
     */
    plotTree : function(npos, opt, animating) {
      var that = this;
      var viz = this.viz;
      var canvas = viz.canvas;
      var config = this.config;
      var D = canvas.getCtx();
      var nodeAlpha = npos.getData("alpha");
      npos.eachSubnode(function(elem) {
        if (opt.plotSubtree(npos, elem) && (elem.exist && elem.drawn)) {
          var from = npos.getAdjacency(elem.id);
          if (!animating) {
            opt.onBeforePlotLine(from);
          }
          that.plotLine(from, canvas, animating);
          if (!animating) {
            opt.onAfterPlotLine(from);
          }
          that.plotTree(elem, opt, animating);
        }
      });
      if (npos.drawn) {
        if (!animating) {
          opt.onBeforePlotNode(npos);
        }
        this.plotNode(npos, canvas, animating);
        if (!animating) {
          opt.onAfterPlotNode(npos);
        }
        if (!opt.hideLabels && (opt.withLabels && nodeAlpha >= 0.95)) {
          this.labels.plotLabel(canvas, npos, opt);
        } else {
          this.labels.hideLabel(npos, false);
        }
      } else {
        this.labels.hideLabel(npos, true);
      }
    },
    /**
     * @param {?} node
     * @param {?} canvas
     * @param {boolean} animating
     * @return {undefined}
     */
    plotNode : function(node, canvas, animating) {
      var f = node.getData("type");
      var ctxObj = this.node.CanvasStyles;
      if (f != "none") {
        var width = node.getData("lineWidth");
        var color = node.getData("color");
        var alpha = node.getData("alpha");
        var ctx = canvas.getCtx();
        ctx.save();
        ctx.lineWidth = width;
        ctx.fillStyle = ctx.strokeStyle = color;
        ctx.globalAlpha = alpha;
        var s;
        for (s in ctxObj) {
          ctx[s] = node.getCanvasStyle(s);
        }
        this.nodeTypes[f].render.call(this, node, canvas, animating);
        ctx.restore();
      }
    },
    /**
     * @param {?} adj
     * @param {?} canvas
     * @param {boolean} animating
     * @return {undefined}
     */
    plotLine : function(adj, canvas, animating) {
      var f = adj.getData("type");
      var ctxObj = this.edge.CanvasStyles;
      if (f != "none") {
        var width = adj.getData("lineWidth");
        var color = adj.getData("color");
        var ctx = canvas.getCtx();
        var nodeFrom = adj.nodeFrom;
        var nodeTo = adj.nodeTo;
        ctx.save();
        ctx.lineWidth = width;
        ctx.fillStyle = ctx.strokeStyle = color;
        /** @type {number} */
        ctx.globalAlpha = Math.min(nodeFrom.getData("alpha"), nodeTo.getData("alpha"), adj.getData("alpha"));
        var s;
        for (s in ctxObj) {
          ctx[s] = adj.getCanvasStyle(s);
        }
        this.edgeTypes[f].render.call(this, adj, canvas, animating);
        ctx.restore();
      }
    }
  };
  Graph.Plot3D = $.merge(Graph.Plot, {
    Interpolator : {
      /**
       * @param {Object} n
       * @param {?} diff
       * @param {?} qualifier
       * @return {undefined}
       */
      linear : function(n, diff, qualifier) {
        var from = n.startPos.getc(true);
        var to = n.endPos.getc(true);
        n.pos.setc(this.compute(from.x, to.x, qualifier), this.compute(from.y, to.y, qualifier), this.compute(from.z, to.z, qualifier));
      }
    },
    /**
     * @param {Object} node
     * @param {Object} canvas
     * @return {undefined}
     */
    plotNode : function(node, canvas) {
      if (node.getData("type") == "none") {
        return;
      }
      this.plotElement(node, canvas, {
        /**
         * @return {?}
         */
        getAlpha : function() {
          return node.getData("alpha");
        }
      });
    },
    /**
     * @param {Object} adj
     * @param {Object} canvas
     * @return {undefined}
     */
    plotLine : function(adj, canvas) {
      if (adj.getData("type") == "none") {
        return;
      }
      this.plotElement(adj, canvas, {
        /**
         * @return {?}
         */
        getAlpha : function() {
          return Math.min(adj.nodeFrom.getData("alpha"), adj.nodeTo.getData("alpha"), adj.getData("alpha"));
        }
      });
    },
    /**
     * @param {Object} elem
     * @param {Object} canvas
     * @param {?} opt_attributes
     * @return {undefined}
     */
    plotElement : function(elem, canvas, opt_attributes) {
      var gl = canvas.getCtx();
      var viewMatrix = new Matrix4;
      var lighting = canvas.config.Scene.Lighting;
      var wcanvas = canvas.canvases[0];
      var program = wcanvas.program;
      var camera = wcanvas.camera;
      if (!elem.geometry) {
        elem.geometry = new (O3D[elem.getData("type")]);
      }
      elem.geometry.update(elem);
      if (!elem.webGLVertexBuffer) {
        /** @type {Array} */
        var normals = [];
        /** @type {Array} */
        var faces = [];
        /** @type {Array} */
        var positions = [];
        /** @type {number} */
        var vertexIndex = 0;
        var geom = elem.geometry;
        /** @type {number} */
        var i = 0;
        var vs = geom.vertices;
        var fs = geom.faces;
        var len = fs.length;
        for (;i < len;i++) {
          var face = fs[i];
          var normal = vs[face.a];
          var n = vs[face.b];
          var v1 = vs[face.c];
          var p0 = face.d ? vs[face.d] : false;
          var position = face.normal;
          normals.push(normal.x, normal.y, normal.z);
          normals.push(n.x, n.y, n.z);
          normals.push(v1.x, v1.y, v1.z);
          if (p0) {
            normals.push(p0.x, p0.y, p0.z);
          }
          positions.push(position.x, position.y, position.z);
          positions.push(position.x, position.y, position.z);
          positions.push(position.x, position.y, position.z);
          if (p0) {
            positions.push(position.x, position.y, position.z);
          }
          faces.push(vertexIndex, vertexIndex + 1, vertexIndex + 2);
          if (p0) {
            faces.push(vertexIndex, vertexIndex + 2, vertexIndex + 3);
            vertexIndex += 4;
          } else {
            vertexIndex += 3;
          }
        }
        elem.webGLVertexBuffer = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, elem.webGLVertexBuffer);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(normals), gl.STATIC_DRAW);
        elem.webGLFaceBuffer = gl.createBuffer();
        gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, elem.webGLFaceBuffer);
        gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, new Uint16Array(faces), gl.STATIC_DRAW);
        /** @type {number} */
        elem.webGLFaceCount = faces.length;
        elem.webGLNormalBuffer = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, elem.webGLNormalBuffer);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(positions), gl.STATIC_DRAW);
      }
      viewMatrix.multiply(camera.matrix, elem.geometry.matrix);
      gl.uniformMatrix4fv(program.viewMatrix, false, viewMatrix.flatten());
      gl.uniformMatrix4fv(program.projectionMatrix, false, camera.projectionMatrix.flatten());
      var normalMatrix = Matrix4.makeInvert(viewMatrix);
      normalMatrix.$transpose();
      gl.uniformMatrix4fv(program.normalMatrix, false, normalMatrix.flatten());
      var color = $.hexToRgb(elem.getData("color"));
      color.push(opt_attributes.getAlpha());
      gl.uniform4f(program.color, color[0] / 255, color[1] / 255, color[2] / 255, color[3]);
      gl.uniform1i(program.enableLighting, lighting.enable);
      if (lighting.enable) {
        if (lighting.ambient) {
          var acolor = lighting.ambient;
          gl.uniform3f(program.ambientColor, acolor[0], acolor[1], acolor[2]);
        }
        if (lighting.directional) {
          var dir = lighting.directional;
          color = dir.color;
          var pos = dir.direction;
          var vd = (new Vector3(pos.x, pos.y, pos.z)).normalize().$scale(-1);
          gl.uniform3f(program.lightingDirection, vd.x, vd.y, vd.z);
          gl.uniform3f(program.directionalColor, color[0], color[1], color[2]);
        }
      }
      gl.bindBuffer(gl.ARRAY_BUFFER, elem.webGLVertexBuffer);
      gl.vertexAttribPointer(program.position, 3, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ARRAY_BUFFER, elem.webGLNormalBuffer);
      gl.vertexAttribPointer(program.normal, 3, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, elem.webGLFaceBuffer);
      gl.drawElements(gl.TRIANGLES, elem.webGLFaceCount, gl.UNSIGNED_SHORT, 0);
    }
  });
  Graph.Label = {};
  Graph.Label.Native = new Class({
    /**
     * @param {?} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.viz = viz;
    },
    /**
     * @param {?} canvas
     * @param {Object} node
     * @param {?} opt
     * @return {undefined}
     */
    plotLabel : function(canvas, node, opt) {
      var ctx = canvas.getCtx();
      var A = node.pos.getc(true);
      ctx.font = node.getLabelData("style") + " " + node.getLabelData("size") + "px " + node.getLabelData("family");
      ctx.textAlign = node.getLabelData("textAlign");
      ctx.fillStyle = ctx.strokeStyle = node.getLabelData("color");
      ctx.textBaseline = node.getLabelData("textBaseline");
      this.renderLabel(canvas, node, opt);
    },
    /**
     * @param {?} canvas
     * @param {Object} node
     * @param {?} opt
     * @return {undefined}
     */
    renderLabel : function(canvas, node, opt) {
      var ctx = canvas.getCtx();
      var pt = node.pos.getc(true);
      ctx.fillText(node.name, pt.x, pt.y + node.getData("height") / 2);
    },
    /** @type {function (): undefined} */
    hideLabel : $.empty,
    /** @type {function (): undefined} */
    hideLabels : $.empty
  });
  Graph.Label.DOM = new Class({
    labelsHidden : false,
    labelContainer : false,
    labels : {},
    /**
     * @return {?}
     */
    getLabelContainer : function() {
      return this.labelContainer ? this.labelContainer : this.labelContainer = document.getElementById(this.viz.config.labelContainer);
    },
    /**
     * @param {?} id
     * @return {?}
     */
    getLabel : function(id) {
      return id in this.labels && this.labels[id] != null ? this.labels[id] : this.labels[id] = document.getElementById(id);
    },
    /**
     * @param {?} adj
     * @return {undefined}
     */
    hideLabels : function(adj) {
      var container = this.getLabelContainer();
      if (adj) {
        /** @type {string} */
        container.style.display = "none";
      } else {
        /** @type {string} */
        container.style.display = "";
      }
      this.labelsHidden = adj;
    },
    /**
     * @param {boolean} dataAndEvents
     * @return {undefined}
     */
    clearLabels : function(dataAndEvents) {
      var id;
      for (id in this.labels) {
        if (dataAndEvents || !this.viz.graph.hasNode(id)) {
          this.disposeLabel(id);
          delete this.labels[id];
        }
      }
    },
    /**
     * @param {string} id
     * @return {undefined}
     */
    disposeLabel : function(id) {
      var elem = this.getLabel(id);
      if (elem && elem.parentNode) {
        elem.parentNode.removeChild(elem);
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @return {undefined}
     */
    hideLabel : function(adj, lab) {
      adj = $.splat(adj);
      /** @type {string} */
      var disp = lab ? "" : "none";
      var y;
      var that = this;
      $.each(adj, function(n) {
        var testElement = that.getLabel(n.id);
        if (testElement) {
          /** @type {string} */
          testElement.style.display = disp;
        }
      });
    },
    /**
     * @param {Object} pos
     * @param {?} canvas
     * @return {?}
     */
    fitsInCanvas : function(pos, canvas) {
      var size = canvas.getSize();
      if (pos.x >= size.width || (pos.x < 0 || (pos.y >= size.height || pos.y < 0))) {
        return false;
      }
      return true;
    }
  });
  Graph.Label.HTML = new Class({
    Implements : Graph.Label.DOM,
    /**
     * @param {?} canvas
     * @param {?} lab
     * @param {?} pending
     * @return {undefined}
     */
    plotLabel : function(canvas, lab, pending) {
      var id = lab.id;
      var from = this.getLabel(id);
      if (!from && !(from = document.getElementById(id))) {
        /** @type {Element} */
        from = document.createElement("div");
        var container = this.getLabelContainer();
        from.id = id;
        /** @type {string} */
        from.className = "node";
        /** @type {string} */
        from.style.position = "absolute";
        pending.onCreateLabel(from, lab);
        container.appendChild(from);
        /** @type {Element} */
        this.labels[lab.id] = from;
      }
      this.placeLabel(from, lab, pending);
    }
  });
  Graph.Label.SVG = new Class({
    Implements : Graph.Label.DOM,
    /**
     * @param {?} canvas
     * @param {?} lab
     * @param {?} pending
     * @return {undefined}
     */
    plotLabel : function(canvas, lab, pending) {
      var id = lab.id;
      var from = this.getLabel(id);
      if (!from && !(from = document.getElementById(id))) {
        /** @type {string} */
        var ns = "http://www.w3.org/2000/svg";
        /** @type {Element} */
        from = document.createElementNS(ns, "svg:text");
        /** @type {Element} */
        var p = document.createElementNS(ns, "svg:tspan");
        from.appendChild(p);
        var container = this.getLabelContainer();
        from.setAttribute("id", id);
        from.setAttribute("class", "node");
        container.appendChild(from);
        pending.onCreateLabel(from, lab);
        /** @type {Element} */
        this.labels[lab.id] = from;
      }
      this.placeLabel(from, lab, pending);
    }
  });
  Graph.Geom = new Class({
    /**
     * @param {?} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.viz = viz;
      this.config = viz.config;
      this.node = viz.config.Node;
      this.edge = viz.config.Edge;
    },
    /**
     * @param {number} x
     * @param {?} attributes
     * @return {undefined}
     */
    translate : function(x, attributes) {
      attributes = $.splat(attributes);
      this.viz.graph.eachNode(function(obj) {
        $.each(attributes, function(prop) {
          obj.getPos(prop).$add(x);
        });
      });
    },
    /**
     * @param {?} node
     * @param {?} canvas
     * @param {Object} callback
     * @return {undefined}
     */
    setRightLevelToShow : function(node, canvas, callback) {
      var level = this.getRightLevelToShow(node, canvas);
      var fx = this.viz.labels;
      var opt = $.merge({
        execShow : true,
        execHide : true,
        /** @type {function (): undefined} */
        onHide : $.empty,
        /** @type {function (): undefined} */
        onShow : $.empty
      }, callback || {});
      node.eachLevel(0, this.config.levelsToShow, function(from) {
        /** @type {number} */
        var flowLevel = from._depth - node._depth;
        if (flowLevel > level) {
          opt.onHide(from);
          if (opt.execHide) {
            /** @type {boolean} */
            from.drawn = false;
            /** @type {boolean} */
            from.exist = false;
            fx.hideLabel(from, false);
          }
        } else {
          opt.onShow(from);
          if (opt.execShow) {
            /** @type {boolean} */
            from.exist = true;
          }
        }
      });
      /** @type {boolean} */
      node.drawn = true;
    },
    /**
     * @param {Object} node
     * @param {?} canvas
     * @return {?}
     */
    getRightLevelToShow : function(node, canvas) {
      var config = this.config;
      var level = config.levelsToShow;
      var constrained = config.constrained;
      if (!constrained) {
        return level;
      }
      for (;!this.treeFitsInCanvas(node, canvas, level) && level > 1;) {
        level--;
      }
      return level;
    }
  });
  var valid = {
    /**
     * @param {?} json
     * @return {?}
     */
    construct : function(json) {
      /** @type {boolean} */
      var isArray = $.type(json) == "array";
      var ans = new Graph(this.graphOptions, this.config.Node, this.config.Edge, this.config.Label);
      if (!isArray) {
        (function(ans, json) {
          ans.addNode(json);
          if (json.children) {
            /** @type {number} */
            var i = 0;
            var ch = json.children;
            for (;i < ch.length;i++) {
              ans.addAdjacence(json, ch[i]);
              arguments.callee(ans, ch[i]);
            }
          }
        })(ans, json);
      } else {
        (function(ans, json) {
          /**
           * @param {string} key
           * @return {?}
           */
          var getNode = function(key) {
            /** @type {number} */
            var i = 0;
            var len = json.length;
            for (;i < len;i++) {
              if (json[i].id == key) {
                return json[i];
              }
            }
            var newNode = {
              id : key,
              name : key
            };
            return ans.addNode(newNode);
          };
          /** @type {number} */
          var i = 0;
          var len = json.length;
          for (;i < len;i++) {
            ans.addNode(json[i]);
            var a = json[i].adjacencies;
            if (a) {
              /** @type {number} */
              var j = 0;
              var al = a.length;
              for (;j < al;j++) {
                var node = a[j];
                var pdataCur = {};
                if (typeof a[j] != "string") {
                  pdataCur = $.merge(node.data, {});
                  node = node.nodeTo;
                }
                ans.addAdjacence(json[i], getNode(node), pdataCur);
              }
            }
          }
        })(ans, json);
      }
      return ans;
    },
    /**
     * @param {Object} json
     * @param {number} i
     * @return {undefined}
     */
    loadJSON : function(json, i) {
      /** @type {Object} */
      this.json = json;
      if (this.labels && this.labels.clearLabels) {
        this.labels.clearLabels(true);
      }
      this.graph = this.construct(json);
      if ($.type(json) != "array") {
        this.root = json.id;
      } else {
        this.root = json[i ? i : 0].id;
      }
    },
    /**
     * @param {string} type
     * @return {?}
     */
    toJSON : function(type) {
      type = type || "tree";
      if (type == "tree") {
        var ans = {};
        var rootNode = this.graph.getNode(this.root);
        ans = function recTree(node) {
          var ans = {};
          ans.id = node.id;
          ans.name = node.name;
          ans.data = node.data;
          /** @type {Array} */
          var ch = [];
          node.eachSubnode(function(n) {
            ch.push(recTree(n));
          });
          /** @type {Array} */
          ans.children = ch;
          return ans;
        }(rootNode);
        return ans;
      } else {
        /** @type {Array} */
        ans = [];
        /** @type {boolean} */
        var T = !!this.graph.getNode(this.root).visited;
        this.graph.eachNode(function(node) {
          var ansNode = {};
          ansNode.id = node.id;
          ansNode.name = node.name;
          ansNode.data = node.data;
          /** @type {Array} */
          var adjs = [];
          node.eachAdjacency(function(adj) {
            var nodeTo = adj.nodeTo;
            if (!!nodeTo.visited === T) {
              var ansAdj = {};
              ansAdj.nodeTo = nodeTo.id;
              ansAdj.data = adj.data;
              adjs.push(ansAdj);
            }
          });
          /** @type {Array} */
          ansNode.adjacencies = adjs;
          ans.push(ansNode);
          /** @type {boolean} */
          node.visited = !T;
        });
        return ans;
      }
    }
  };
  var Layout = $jit.Layouts = {};
  var column = {
    label : null,
    /**
     * @param {?} adj
     * @param {?} lab
     * @param {?} event
     * @return {undefined}
     */
    compute : function(adj, lab, event) {
      this.initializeLabel(event);
      var label = this.label;
      var style = label.style;
      adj.eachNode(function(n) {
        var autoWidth = n.getData("autoWidth");
        var autoHeight = n.getData("autoHeight");
        if (autoWidth || autoHeight) {
          delete n.data.$width;
          delete n.data.$height;
          delete n.data.$dim;
          var width = n.getData("width");
          var height = n.getData("height");
          /** @type {string} */
          style.width = autoWidth ? "auto" : width + "px";
          /** @type {string} */
          style.height = autoHeight ? "auto" : height + "px";
          label.innerHTML = n.name;
          var offsetWidth = label.offsetWidth;
          var offsetHeight = label.offsetHeight;
          var nodes = n.getData("type");
          if ($.indexOf(["circle", "square", "triangle", "star"], nodes) === -1) {
            n.setData("width", offsetWidth);
            n.setData("height", offsetHeight);
          } else {
            var dim = offsetWidth > offsetHeight ? offsetWidth : offsetHeight;
            n.setData("width", dim);
            n.setData("height", dim);
            n.setData("dim", dim);
          }
        }
      });
    },
    /**
     * @param {?} opt
     * @return {undefined}
     */
    initializeLabel : function(opt) {
      if (!this.label) {
        /** @type {Element} */
        this.label = document.createElement("div");
        document.body.appendChild(this.label);
      }
      this.setLabelStyles(opt);
    },
    /**
     * @param {?} opt
     * @return {undefined}
     */
    setLabelStyles : function(opt) {
      $.extend(this.label.style, {
        visibility : "hidden",
        position : "absolute",
        width : "auto",
        height : "auto"
      });
      /** @type {string} */
      this.label.className = "jit-autoadjust-label";
    }
  };
  Layout.Tree = function() {
    /**
     * @param {?} graph
     * @param {Node} config
     * @param {?} level
     * @param {string} orn
     * @param {Object} prop
     * @return {?}
     */
    function getBoundaries(graph, config, level, orn, prop) {
      var dim = config.Node;
      var multitree = config.multitree;
      if (dim.overridable) {
        /** @type {number} */
        var w = -1;
        /** @type {number} */
        var h = -1;
        graph.eachNode(function(n) {
          if (n._depth == level && (!multitree || "$orn" in n.data && n.data.$orn == orn)) {
            var dw = n.getData("width", prop);
            var dh = n.getData("height", prop);
            w = w < dw ? dw : w;
            h = h < dh ? dh : h;
          }
        });
        return{
          width : w < 0 ? dim.width : w,
          height : h < 0 ? dim.height : h
        };
      } else {
        return dim;
      }
    }
    /**
     * @param {?} node
     * @param {Object} prop
     * @param {?} val
     * @param {string} orn
     * @return {undefined}
     */
    function movetree(node, prop, val, orn) {
      /** @type {string} */
      var p = orn == "left" || orn == "right" ? "y" : "x";
      node.getPos(prop)[p] += val;
    }
    /**
     * @param {?} attributes
     * @param {?} ans
     * @return {?}
     */
    function moveextent(attributes, ans) {
      /** @type {Array} */
      var a = [];
      $.each(attributes, function(next_scope) {
        /** @type {Array.<?>} */
        next_scope = next_callback.call(next_scope);
        next_scope[0] += ans;
        next_scope[1] += ans;
        a.push(next_scope);
      });
      return a;
    }
    /**
     * @param {Array} ps
     * @param {Array} qs
     * @return {?}
     */
    function merge(ps, qs) {
      if (ps.length == 0) {
        return qs;
      }
      if (qs.length == 0) {
        return ps;
      }
      var J = ps.shift();
      var I = qs.shift();
      return[[J[0], I[1]]].concat(merge(ps, qs));
    }
    /**
     * @param {Array} ls
     * @param {Array} def
     * @return {?}
     */
    function mergelist(ls, def) {
      def = def || [];
      if (ls.length == 0) {
        return def;
      }
      var ps = ls.pop();
      return mergelist(ls, merge(ps, def));
    }
    /**
     * @param {Array} ext1
     * @param {Array} ext2
     * @param {?} subtreeOffset
     * @param {number} siblingOffset
     * @param {number} i
     * @return {?}
     */
    function fit(ext1, ext2, subtreeOffset, siblingOffset, i) {
      if (ext1.length <= i || ext2.length <= i) {
        return 0;
      }
      var p = ext1[i][1];
      var q = ext2[i][0];
      return Math.max(fit(ext1, ext2, subtreeOffset, siblingOffset, ++i) + subtreeOffset, p - q + siblingOffset);
    }
    /**
     * @param {?} es
     * @param {?} subtreeOffset
     * @param {number} siblingOffset
     * @return {?}
     */
    function fitlistl(es, subtreeOffset, siblingOffset) {
      /**
       * @param {Array} acc
       * @param {Array} es
       * @param {number} i
       * @return {?}
       */
      function $fitlistl(acc, es, i) {
        if (es.length <= i) {
          return[];
        }
        var e = es[i];
        var ans = fit(acc, e, subtreeOffset, siblingOffset, 0);
        return[ans].concat($fitlistl(merge(acc, moveextent(e, ans)), es, ++i));
      }
      return $fitlistl([], es, 0);
    }
    /**
     * @param {Array} es
     * @param {?} subtreeOffset
     * @param {number} siblingOffset
     * @return {?}
     */
    function fitlistr(es, subtreeOffset, siblingOffset) {
      /**
       * @param {?} acc
       * @param {Array} es
       * @param {number} i
       * @return {?}
       */
      function $fitlistr(acc, es, i) {
        if (es.length <= i) {
          return[];
        }
        var e = es[i];
        /** @type {number} */
        var ans = -fit(e, acc, subtreeOffset, siblingOffset, 0);
        return[ans].concat($fitlistr(merge(moveextent(e, ans), acc), es, ++i));
      }
      /** @type {Array.<?>} */
      es = next_callback.call(es);
      var ans = $fitlistr([], es.reverse(), 0);
      return ans.reverse();
    }
    /**
     * @param {?} es
     * @param {?} subtreeOffset
     * @param {number} siblingOffset
     * @param {string} align
     * @return {?}
     */
    function fitlist(es, subtreeOffset, siblingOffset, align) {
      var esl = fitlistl(es, subtreeOffset, siblingOffset);
      var esr = fitlistr(es, subtreeOffset, siblingOffset);
      if (align == "left") {
        esr = esl;
      } else {
        if (align == "right") {
          esl = esr;
        }
      }
      /** @type {number} */
      var i = 0;
      /** @type {Array} */
      var prevSources = [];
      for (;i < esl.length;i++) {
        /** @type {number} */
        prevSources[i] = (esl[i] + esr[i]) / 2;
      }
      return prevSources;
    }
    /**
     * @param {?} graph
     * @param {?} node
     * @param {Object} prop
     * @param {Element} config
     * @param {string} orn
     * @return {undefined}
     */
    function design(graph, node, prop, config, orn) {
      /**
       * @param {Object} node
       * @param {boolean} maxsize
       * @param {number} acum
       * @return {?}
       */
      function $design(node, maxsize, acum) {
        var r = node.getData(s, prop);
        var notsval = maxsize || node.getData(nots, prop);
        /** @type {Array} */
        var trees = [];
        /** @type {Array} */
        var extents = [];
        /** @type {boolean} */
        var chmaxsize = false;
        var chacum = notsval + config.levelDistance;
        node.eachSubnode(function(n) {
          if (n.exist && (!multitree || "$orn" in n.data && n.data.$orn == orn)) {
            if (!chmaxsize) {
              chmaxsize = getBoundaries(graph, config, n._depth, orn, prop);
            }
            var s = $design(n, chmaxsize[nots], acum + chacum);
            trees.push(s.tree);
            extents.push(s.extent);
          }
        });
        var positions = fitlist(extents, subtreeOffset, siblingOffset, align);
        /** @type {number} */
        var i = 0;
        /** @type {Array} */
        var ac = [];
        /** @type {Array} */
        var pextents = [];
        for (;i < trees.length;i++) {
          movetree(trees[i], prop, positions[i], orn);
          pextents.push(moveextent(extents[i], positions[i]));
        }
        /** @type {Array} */
        var extent = [[-r / 2, r / 2]].concat(mergelist(pextents));
        /** @type {number} */
        node.getPos(prop)[p] = 0;
        if (orn == "top" || orn == "left") {
          /** @type {number} */
          node.getPos(prop)[notp] = acum;
        } else {
          /** @type {number} */
          node.getPos(prop)[notp] = -acum;
        }
        return{
          tree : node,
          extent : extent
        };
      }
      var multitree = config.multitree;
      /** @type {Array} */
      var auxp = ["x", "y"];
      /** @type {Array} */
      var auxs = ["width", "height"];
      /** @type {number} */
      var ind = +(orn == "left" || orn == "right");
      var p = auxp[ind];
      var notp = auxp[1 - ind];
      var cnode = config.Node;
      var s = auxs[ind];
      var nots = auxs[1 - ind];
      var siblingOffset = config.siblingOffset;
      var subtreeOffset = config.subtreeOffset;
      var align = config.align;
      $design(node, false, 0);
    }
    /** @type {function (this:(Array.<T>|string|{length: number}), *=, *=): Array.<T>} */
    var next_callback = Array.prototype.slice;
    return new Class({
      /**
       * @param {number} adj
       * @param {?} type
       * @return {undefined}
       */
      compute : function(adj, type) {
        var lab = adj || "start";
        var node = this.graph.getNode(this.root);
        $.extend(node, {
          drawn : true,
          exist : true,
          selected : true
        });
        column.compute(this.graph, lab, this.config);
        if (!!type || !("_depth" in node)) {
          this.graph.computeLevels(this.root, 0, "ignore");
        }
        this.computePositions(node, lab);
      },
      /**
       * @param {?} node
       * @param {Object} prop
       * @return {undefined}
       */
      computePositions : function(node, prop) {
        var config = this.config;
        var multitree = config.multitree;
        var align = config.align;
        var indent = align !== "center" && config.indent;
        var orn = config.orientation;
        /** @type {Array} */
        var attributes = multitree ? ["top", "right", "bottom", "left"] : [orn];
        var that = this;
        $.each(attributes, function(orn) {
          design(that.graph, node, prop, that.config, orn, prop);
          var i = ["x", "y"][+(orn == "left" || orn == "right")];
          (function red(node) {
            node.eachSubnode(function(n) {
              if (n.exist && (!multitree || "$orn" in n.data && n.data.$orn == orn)) {
                n.getPos(prop)[i] += node.getPos(prop)[i];
                if (indent) {
                  n.getPos(prop)[i] += align == "left" ? indent : -indent;
                }
                red(n);
              }
            });
          })(node);
        });
      }
    });
  }();
  $jit.ST = function() {
    /**
     * @param {Object} node
     * @return {?}
     */
    function getNodesToHide(node) {
      node = node || this.clickedNode;
      if (!this.config.constrained) {
        return[];
      }
      var Geom = this.geom;
      var graph = this.graph;
      var canvas = this.canvas;
      var level = node._depth;
      /** @type {Array} */
      var matched = [];
      graph.eachNode(function(n) {
        if (n.exist && !n.selected) {
          if (n.isDescendantOf(node.id)) {
            if (n._depth <= level) {
              matched.push(n);
            }
          } else {
            matched.push(n);
          }
        }
      });
      var leafLevel = Geom.getRightLevelToShow(node, canvas);
      node.eachLevel(leafLevel, leafLevel, function(n) {
        if (n.exist && !n.selected) {
          matched.push(n);
        }
      });
      /** @type {number} */
      var i = 0;
      for (;i < nodesInPath.length;i++) {
        var n = this.graph.getNode(nodesInPath[i]);
        if (!n.isDescendantOf(node.id)) {
          matched.push(n);
        }
      }
      return matched;
    }
    /**
     * @param {(number|string)} node
     * @return {?}
     */
    function getNodesToShow(node) {
      /** @type {Array} */
      var matched = [];
      var config = this.config;
      node = node || this.clickedNode;
      this.clickedNode.eachLevel(0, config.levelsToShow, function(n) {
        if (config.multitree && (!("$orn" in n.data) && n.anySubnode(function(n) {
          return n.exist && !n.drawn;
        }))) {
          matched.push(n);
        } else {
          if (n.drawn && !n.anySubnode("drawn")) {
            matched.push(n);
          }
        }
      });
      return matched;
    }
    /** @type {Array} */
    var nodesInPath = [];
    return new Class({
      Implements : [valid, Extras, Layout.Tree],
      /**
       * @param {?} controller
       * @return {undefined}
       */
      initialize : function(controller) {
        var $ST = $jit.ST;
        var config = {
          levelsToShow : 2,
          levelDistance : 30,
          constrained : true,
          Node : {
            type : "rectangle"
          },
          duration : 700,
          offsetX : 0,
          offsetY : 0
        };
        this.controller = this.config = $.merge(Options("Canvas", "Fx", "Tree", "Node", "Edge", "Controller", "Tips", "NodeStyles", "Events", "Navigation", "Label"), config, controller);
        var canvasConfig = this.config;
        if (canvasConfig.useCanvas) {
          this.canvas = canvasConfig.useCanvas;
          /** @type {string} */
          this.config.labelContainer = this.canvas.id + "-label";
        } else {
          if (canvasConfig.background) {
            canvasConfig.background = $.merge({
              type : "Circles"
            }, canvasConfig.background);
          }
          this.canvas = new Canvas(this, canvasConfig);
          /** @type {string} */
          this.config.labelContainer = (typeof canvasConfig.injectInto == "string" ? canvasConfig.injectInto : canvasConfig.injectInto.id) + "-label";
        }
        this.graphOptions = {
          /** @type {function (number, (number|string)): undefined} */
          klass : Vector
        };
        this.graph = new Graph(this.graphOptions, this.config.Node, this.config.Edge);
        this.labels = new $ST.Label[canvasConfig.Label.type](this);
        this.fx = new $ST.Plot(this, $ST);
        this.op = new $ST.Op(this);
        this.group = new $ST.Group(this);
        this.geom = new $ST.Geom(this);
        /** @type {null} */
        this.clickedNode = null;
        this.initializeExtras();
      },
      /**
       * @return {undefined}
       */
      plot : function() {
        this.fx.plot(this.controller);
      },
      /**
       * @param {number} pos
       * @param {string} method
       * @param {?} lab
       * @return {undefined}
       */
      switchPosition : function(pos, method, lab) {
        var Geom = this.geom;
        var Plot = this.fx;
        var that = this;
        if (!Plot.busy) {
          /** @type {boolean} */
          Plot.busy = true;
          this.contract({
            /**
             * @return {undefined}
             */
            onComplete : function() {
              Geom.switchOrientation(pos);
              that.compute("end", false);
              /** @type {boolean} */
              Plot.busy = false;
              if (method == "animate") {
                that.onClick(that.clickedNode.id, lab);
              } else {
                if (method == "replot") {
                  that.select(that.clickedNode.id, lab);
                }
              }
            }
          }, pos);
        }
      },
      /**
       * @param {number} align
       * @param {string} method
       * @param {?} lab
       * @return {undefined}
       */
      switchAlignment : function(align, method, lab) {
        /** @type {number} */
        this.config.align = align;
        if (method == "animate") {
          this.select(this.clickedNode.id, lab);
        } else {
          if (method == "replot") {
            this.onClick(this.clickedNode.id, lab);
          }
        }
      },
      /**
       * @param {?} id
       * @return {undefined}
       */
      addNodeInPath : function(id) {
        nodesInPath.push(id);
        this.select(this.clickedNode && this.clickedNode.id || this.root);
      },
      /**
       * @param {?} dataAndEvents
       * @return {undefined}
       */
      clearNodesInPath : function(dataAndEvents) {
        /** @type {number} */
        nodesInPath.length = 0;
        this.select(this.clickedNode && this.clickedNode.id || this.root);
      },
      /**
       * @return {undefined}
       */
      refresh : function() {
        this.reposition();
        this.select(this.clickedNode && this.clickedNode.id || this.root);
      },
      /**
       * @return {undefined}
       */
      reposition : function() {
        this.graph.computeLevels(this.root, 0, "ignore");
        this.geom.setRightLevelToShow(this.clickedNode, this.canvas);
        this.graph.eachNode(function(n) {
          if (n.exist) {
            /** @type {boolean} */
            n.drawn = true;
          }
        });
        this.compute("end");
      },
      /**
       * @param {Array} node
       * @param {?} onComplete
       * @return {undefined}
       */
      requestNodes : function(node, onComplete) {
        var handler = $.merge(this.controller, onComplete);
        var lev = this.config.levelsToShow;
        if (handler.request) {
          /** @type {Array} */
          var leaves = [];
          var d = node._depth;
          node.eachLevel(0, lev, function(n) {
            if (n.drawn && !n.anySubnode()) {
              leaves.push(n);
              /** @type {number} */
              n._level = lev - (n._depth - d);
            }
          });
          this.group.requestNodes(leaves, handler);
        } else {
          handler.onComplete();
        }
      },
      /**
       * @param {?} onComplete
       * @param {number} switched
       * @return {undefined}
       */
      contract : function(onComplete, switched) {
        var orn = this.config.orientation;
        var Geom = this.geom;
        var Group = this.group;
        if (switched) {
          Geom.switchOrientation(switched);
        }
        var nodes = getNodesToHide.call(this);
        if (switched) {
          Geom.switchOrientation(orn);
        }
        Group.contract(nodes, $.merge(this.controller, onComplete));
      },
      /**
       * @param {?} node
       * @param {?} onComplete
       * @return {undefined}
       */
      move : function(node, onComplete) {
        this.compute("end", false);
        var move = onComplete.Move;
        var offset = {
          x : move.offsetX,
          y : move.offsetY
        };
        if (move.enable) {
          this.geom.translate(node.endPos.add(offset).$scale(-1), "end");
        }
        this.fx.animate($.merge(this.controller, {
          modes : ["linear"]
        }, onComplete));
      },
      /**
       * @param {?} node
       * @param {?} onComplete
       * @return {undefined}
       */
      expand : function(node, onComplete) {
        var vvar = getNodesToShow.call(this, node);
        this.group.expand(vvar, $.merge(this.controller, onComplete));
      },
      /**
       * @param {?} node
       * @return {undefined}
       */
      selectPath : function(node) {
        /**
         * @param {Object} node
         * @return {undefined}
         */
        function path(node) {
          if (node == null || node.selected) {
            return;
          }
          /** @type {boolean} */
          node.selected = true;
          $.each(that.group.getSiblings([node])[node.id], function(n) {
            /** @type {boolean} */
            n.exist = true;
            /** @type {boolean} */
            n.drawn = true;
          });
          var indents = node.getParents();
          indents = indents.length > 0 ? indents[0] : null;
          path(indents);
        }
        var that = this;
        this.graph.eachNode(function(pane) {
          /** @type {boolean} */
          pane.selected = false;
        });
        /** @type {number} */
        var i = 0;
        /** @type {Array} */
        var codeSegments = [node.id].concat(nodesInPath);
        for (;i < codeSegments.length;i++) {
          path(this.graph.getNode(codeSegments[i]));
        }
      },
      /**
       * @param {?} from
       * @param {string} method
       * @param {Object} onComplete
       * @return {undefined}
       */
      setRoot : function(from, method, onComplete) {
        /**
         * @return {undefined}
         */
        function $setRoot() {
          if (this.config.multitree && clickedNode.data.$orn) {
            var orn = clickedNode.data.$orn;
            var opp = {
              left : "right",
              right : "left",
              top : "bottom",
              bottom : "top"
            }[orn];
            rootNode.data.$orn = opp;
            (function tag(node) {
              node.eachSubnode(function(n) {
                if (n.id != from) {
                  n.data.$orn = opp;
                  tag(n);
                }
              });
            })(rootNode);
            delete clickedNode.data.$orn;
          }
          this.root = from;
          this.clickedNode = clickedNode;
          this.graph.computeLevels(this.root, 0, "ignore");
          this.geom.setRightLevelToShow(clickedNode, canvas, {
            execHide : false,
            /**
             * @param {?} adj
             * @return {undefined}
             */
            onShow : function(adj) {
              if (!adj.drawn) {
                /** @type {boolean} */
                adj.drawn = true;
                adj.setData("alpha", 1, "end");
                adj.setData("alpha", 0);
                adj.pos.setc(clickedNode.pos.x, clickedNode.pos.y);
              }
            }
          });
          this.compute("end");
          /** @type {boolean} */
          this.busy = true;
          this.fx.animate({
            modes : ["linear", "node-property:alpha"],
            /**
             * @return {undefined}
             */
            onComplete : function() {
              /** @type {boolean} */
              that.busy = false;
              that.onClick(from, {
                /**
                 * @return {undefined}
                 */
                onComplete : function() {
                  if (onComplete) {
                    onComplete.onComplete();
                  }
                }
              });
            }
          });
        }
        if (this.busy) {
          return;
        }
        /** @type {boolean} */
        this.busy = true;
        var that = this;
        var canvas = this.canvas;
        var rootNode = this.graph.getNode(this.root);
        var clickedNode = this.graph.getNode(from);
        delete rootNode.data.$orns;
        if (method == "animate") {
          $setRoot.call(this);
          that.selectPath(clickedNode);
        } else {
          if (method == "replot") {
            $setRoot.call(this);
            this.select(this.root);
          }
        }
      },
      /**
       * @param {?} subtree
       * @param {string} method
       * @param {Object} onComplete
       * @return {undefined}
       */
      addSubtree : function(subtree, method, onComplete) {
        if (method == "replot") {
          this.op.sum(subtree, $.extend({
            type : "replot"
          }, onComplete || {}));
        } else {
          if (method == "animate") {
            this.op.sum(subtree, $.extend({
              type : "fade:seq"
            }, onComplete || {}));
          }
        }
      },
      /**
       * @param {?} id
       * @param {?} removeRoot
       * @param {string} method
       * @param {Object} onComplete
       * @return {undefined}
       */
      removeSubtree : function(id, removeRoot, method, onComplete) {
        var n = this.graph.getNode(id);
        /** @type {Array} */
        var selected = [];
        n.eachLevel(+!removeRoot, false, function(row) {
          selected.push(row.id);
        });
        if (method == "replot") {
          this.op.removeNode(selected, $.extend({
            type : "replot"
          }, onComplete || {}));
        } else {
          if (method == "animate") {
            this.op.removeNode(selected, $.extend({
              type : "fade:seq"
            }, onComplete || {}));
          }
        }
      },
      /**
       * @param {boolean} id
       * @param {boolean} lab
       * @return {undefined}
       */
      select : function(id, lab) {
        var group = this.group;
        var geom = this.geom;
        var from = this.graph.getNode(id);
        var canvas = this.canvas;
        var root = this.graph.getNode(this.root);
        var complete = $.merge(this.controller, lab);
        var that = this;
        complete.onBeforeCompute(from);
        this.selectPath(from);
        this.clickedNode = from;
        this.requestNodes(from, {
          /**
           * @return {undefined}
           */
          onComplete : function() {
            group.hide(group.prepare(getNodesToHide.call(that)), complete);
            geom.setRightLevelToShow(from, canvas);
            that.compute("current");
            that.graph.eachNode(function(node) {
              var pos = node.pos.getc(true);
              node.startPos.setc(pos.x, pos.y);
              node.endPos.setc(pos.x, pos.y);
              /** @type {boolean} */
              node.visited = false;
            });
            var offset = {
              x : complete.offsetX,
              y : complete.offsetY
            };
            that.geom.translate(from.endPos.add(offset).$scale(-1), ["start", "current", "end"]);
            group.show(getNodesToShow.call(that));
            that.plot();
            complete.onAfterCompute(that.clickedNode);
            complete.onComplete();
          }
        });
      },
      /**
       * @param {?} adj
       * @param {?} lab
       * @return {undefined}
       */
      onClick : function(adj, lab) {
        var canvas = this.canvas;
        var that = this;
        var Geom = this.geom;
        var config = this.config;
        var innerController = {
          Move : {
            enable : true,
            offsetX : config.offsetX || 0,
            offsetY : config.offsetY || 0
          },
          setRightLevelToShowConfig : false,
          /** @type {function (): undefined} */
          onBeforeRequest : $.empty,
          /** @type {function (): undefined} */
          onBeforeContract : $.empty,
          /** @type {function (): undefined} */
          onBeforeMove : $.empty,
          /** @type {function (): undefined} */
          onBeforeExpand : $.empty
        };
        var complete = $.merge(this.controller, innerController, lab);
        if (!this.busy) {
          /** @type {boolean} */
          this.busy = true;
          var from = this.graph.getNode(adj);
          this.selectPath(from, this.clickedNode);
          this.clickedNode = from;
          complete.onBeforeCompute(from);
          complete.onBeforeRequest(from);
          this.requestNodes(from, {
            /**
             * @return {undefined}
             */
            onComplete : function() {
              complete.onBeforeContract(from);
              that.contract({
                /**
                 * @return {undefined}
                 */
                onComplete : function() {
                  Geom.setRightLevelToShow(from, canvas, complete.setRightLevelToShowConfig);
                  complete.onBeforeMove(from);
                  that.move(from, {
                    Move : complete.Move,
                    /**
                     * @return {undefined}
                     */
                    onComplete : function() {
                      complete.onBeforeExpand(from);
                      that.expand(from, {
                        /**
                         * @return {undefined}
                         */
                        onComplete : function() {
                          /** @type {boolean} */
                          that.busy = false;
                          complete.onAfterCompute(adj);
                          complete.onComplete();
                        }
                      });
                    }
                  });
                }
              });
            }
          });
        }
      }
    });
  }();
  /** @type {boolean} */
  $jit.ST.$extend = true;
  $jit.ST.Op = new Class({
    Implements : Graph.Op
  });
  $jit.ST.Group = new Class({
    /**
     * @param {Object} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      /** @type {Object} */
      this.viz = viz;
      this.canvas = viz.canvas;
      this.config = viz.config;
      this.animation = new Animation;
      /** @type {null} */
      this.nodes = null;
    },
    /**
     * @param {Array} nodes
     * @param {?} controller
     * @return {undefined}
     */
    requestNodes : function(nodes, controller) {
      /** @type {number} */
      var counter = 0;
      var len = nodes.length;
      var nodeSelected = {};
      /**
       * @return {undefined}
       */
      var complete = function() {
        controller.onComplete();
      };
      var viz = this.viz;
      if (len == 0) {
        complete();
      }
      /** @type {number} */
      var i = 0;
      for (;i < len;i++) {
        nodeSelected[nodes[i].id] = nodes[i];
        controller.request(nodes[i].id, nodes[i]._level, {
          /**
           * @param {?} adj
           * @param {?} lab
           * @return {undefined}
           */
          onComplete : function(adj, lab) {
            if (lab && lab.children) {
              lab.id = adj;
              viz.op.sum(lab, {
                type : "nothing"
              });
            }
            if (++counter == len) {
              viz.graph.computeLevels(viz.root, 0);
              complete();
            }
          }
        });
      }
    },
    /**
     * @param {Object} nodes
     * @param {Object} controller
     * @return {undefined}
     */
    contract : function(nodes, controller) {
      var viz = this.viz;
      var that = this;
      nodes = this.prepare(nodes);
      this.animation.setOptions($.merge(controller, {
        $animating : false,
        /**
         * @param {?} adj
         * @return {undefined}
         */
        compute : function(adj) {
          if (adj == 1) {
            /** @type {number} */
            adj = 0.99;
          }
          that.plotStep(1 - adj, controller, this.$animating);
          /** @type {string} */
          this.$animating = "contract";
        },
        /**
         * @return {undefined}
         */
        complete : function() {
          that.hide(nodes, controller);
        }
      })).start();
    },
    /**
     * @param {Object} nodes
     * @param {Object} controller
     * @return {undefined}
     */
    hide : function(nodes, controller) {
      var viz = this.viz;
      /** @type {number} */
      var i = 0;
      for (;i < nodes.length;i++) {
        if (true || (!controller || !controller.request)) {
          nodes[i].eachLevel(1, false, function(owner) {
            if (owner.exist) {
              $.extend(owner, {
                drawn : false,
                exist : false
              });
            }
          });
        } else {
          /** @type {Array} */
          var selected = [];
          nodes[i].eachLevel(1, false, function(row) {
            selected.push(row.id);
          });
          viz.op.removeNode(selected, {
            type : "nothing"
          });
          viz.labels.clearLabels();
        }
      }
      controller.onComplete();
    },
    /**
     * @param {?} name
     * @param {Object} controller
     * @return {undefined}
     */
    expand : function(name, controller) {
      var that = this;
      this.show(name);
      this.animation.setOptions($.merge(controller, {
        $animating : false,
        /**
         * @param {?} adj
         * @return {undefined}
         */
        compute : function(adj) {
          that.plotStep(adj, controller, this.$animating);
          /** @type {string} */
          this.$animating = "expand";
        },
        /**
         * @return {undefined}
         */
        complete : function() {
          that.plotStep(undefined, controller, false);
          controller.onComplete();
        }
      })).start();
    },
    /**
     * @param {?} attributes
     * @return {undefined}
     */
    show : function(attributes) {
      var config = this.config;
      this.prepare(attributes);
      $.each(attributes, function(n) {
        if (config.multitree && !("$orn" in n.data)) {
          delete n.data.$orns;
          /** @type {string} */
          var orns = " ";
          n.eachSubnode(function(n) {
            if ("$orn" in n.data && (orns.indexOf(n.data.$orn) < 0 && (n.exist && !n.drawn))) {
              orns += n.data.$orn + " ";
            }
          });
          n.data.$orns = orns;
        }
        n.eachLevel(0, config.levelsToShow, function(n) {
          if (n.exist) {
            /** @type {boolean} */
            n.drawn = true;
          }
        });
      });
    },
    /**
     * @param {?} nodes
     * @return {?}
     */
    prepare : function(nodes) {
      this.nodes = this.getNodesWithChildren(nodes);
      return this.nodes;
    },
    /**
     * @param {Array} nodes
     * @return {?}
     */
    getNodesWithChildren : function(nodes) {
      /** @type {Array} */
      var ans = [];
      var config = this.config;
      var root = this.viz.root;
      nodes.sort(function(a, b) {
        return(a._depth <= b._depth) - (a._depth >= b._depth);
      });
      /** @type {number} */
      var i = 0;
      for (;i < nodes.length;i++) {
        if (nodes[i].anySubnode("exist")) {
          /** @type {number} */
          var j = i + 1;
          /** @type {boolean} */
          var found = false;
          for (;!found && j < nodes.length;j++) {
            if (!config.multitree || "$orn" in nodes[j].data) {
              found = found || nodes[i].isDescendantOf(nodes[j].id);
            }
          }
          if (!found) {
            ans.push(nodes[i]);
          }
        }
      }
      return ans;
    },
    /**
     * @param {number} delta
     * @param {Object} controller
     * @param {boolean} animating
     * @return {undefined}
     */
    plotStep : function(delta, controller, animating) {
      var viz = this.viz;
      var config = this.config;
      var canvas = viz.canvas;
      var cctx = canvas.getCtx();
      var nodes = this.nodes;
      var i;
      var node;
      var nds = {};
      /** @type {number} */
      i = 0;
      for (;i < nodes.length;i++) {
        node = nodes[i];
        /** @type {Array} */
        nds[node.id] = [];
        var root = config.multitree && !("$orn" in node.data);
        var orns = root && node.data.$orns;
        node.eachSubgraph(function(n) {
          if (root && (orns && (orns.indexOf(n.data.$orn) > 0 && n.drawn))) {
            /** @type {boolean} */
            n.drawn = false;
            nds[node.id].push(n);
          } else {
            if ((!root || !orns) && n.drawn) {
              /** @type {boolean} */
              n.drawn = false;
              nds[node.id].push(n);
            }
          }
        });
        /** @type {boolean} */
        node.drawn = true;
      }
      if (nodes.length > 0) {
        viz.fx.plot();
      }
      for (i in nds) {
        $.each(nds[i], function(n) {
          /** @type {boolean} */
          n.drawn = true;
        });
      }
      /** @type {number} */
      i = 0;
      for (;i < nodes.length;i++) {
        node = nodes[i];
        cctx.save();
        viz.fx.plotSubtree(node, controller, delta, animating);
        cctx.restore();
      }
    },
    /**
     * @param {?} attributes
     * @return {?}
     */
    getSiblings : function(attributes) {
      var siblings = {};
      $.each(attributes, function(n) {
        var par = n.getParents();
        if (par.length == 0) {
          /** @type {Array} */
          siblings[n.id] = [n];
        } else {
          /** @type {Array} */
          var assigns = [];
          par[0].eachSubnode(function(vvar) {
            assigns.push(vvar);
          });
          /** @type {Array} */
          siblings[n.id] = assigns;
        }
      });
      return siblings;
    }
  });
  $jit.ST.Geom = new Class({
    Implements : Graph.Geom,
    /**
     * @param {number} orn
     * @return {undefined}
     */
    switchOrientation : function(orn) {
      /** @type {number} */
      this.config.orientation = orn;
    },
    /**
     * @return {?}
     */
    dispatch : function() {
      /** @type {Array.<?>} */
      var args = Array.prototype.slice.call(arguments);
      var s = args.shift();
      /** @type {number} */
      var args_length = args.length;
      /**
       * @param {?} a
       * @return {?}
       */
      var val = function(a) {
        return typeof a == "function" ? a() : a;
      };
      if (args_length == 2) {
        return s == "top" || s == "bottom" ? val(args[0]) : val(args[1]);
      } else {
        if (args_length == 4) {
          switch(s) {
            case "top":
              return val(args[0]);
            case "right":
              return val(args[1]);
            case "bottom":
              return val(args[2]);
            case "left":
              return val(args[3]);
          }
        }
      }
      return undefined;
    },
    /**
     * @param {Object} node
     * @param {boolean} dataAndEvents
     * @return {?}
     */
    getSize : function(node, dataAndEvents) {
      var data = node.data;
      var config = this.config;
      var siblingOffset = config.siblingOffset;
      var route = config.multitree && ("$orn" in data && data.$orn) || config.orientation;
      var h = node.getData("width") + siblingOffset;
      var w = node.getData("height") + siblingOffset;
      if (!dataAndEvents) {
        return this.dispatch(route, w, h);
      } else {
        return this.dispatch(route, h, w);
      }
    },
    /**
     * @param {?} node
     * @param {number} level
     * @param {Function} leaf
     * @return {?}
     */
    getTreeBaseSize : function(node, level, leaf) {
      var size = this.getSize(node, true);
      /** @type {number} */
      var baseHeight = 0;
      var that = this;
      if (leaf(level, node)) {
        return size;
      }
      if (level === 0) {
        return 0;
      }
      node.eachSubnode(function(elem) {
        baseHeight += that.getTreeBaseSize(elem, level - 1, leaf);
      });
      return(size > baseHeight ? size : baseHeight) + this.config.subtreeOffset;
    },
    /**
     * @param {?} node
     * @param {string} type
     * @param {?} s
     * @return {?}
     */
    getEdge : function(node, type, s) {
      /**
       * @param {number} mayParseLabeledStatementInstead
       * @param {number} recurring
       * @return {?}
       */
      var $C = function(mayParseLabeledStatementInstead, recurring) {
        return function() {
          return node.pos.add(new Vector(mayParseLabeledStatementInstead, recurring));
        };
      };
      var dim = this.node;
      var w = node.getData("width");
      var h = node.getData("height");
      if (type == "begin") {
        if (dim.align == "center") {
          return this.dispatch(s, $C(0, h / 2), $C(-w / 2, 0), $C(0, -h / 2), $C(w / 2, 0));
        } else {
          if (dim.align == "left") {
            return this.dispatch(s, $C(0, h), $C(0, 0), $C(0, 0), $C(w, 0));
          } else {
            if (dim.align == "right") {
              return this.dispatch(s, $C(0, 0), $C(-w, 0), $C(0, -h), $C(0, 0));
            } else {
              throw "align: not implemented";
            }
          }
        }
      } else {
        if (type == "end") {
          if (dim.align == "center") {
            return this.dispatch(s, $C(0, -h / 2), $C(w / 2, 0), $C(0, h / 2), $C(-w / 2, 0));
          } else {
            if (dim.align == "left") {
              return this.dispatch(s, $C(0, 0), $C(w, 0), $C(0, h), $C(0, 0));
            } else {
              if (dim.align == "right") {
                return this.dispatch(s, $C(0, -h), $C(0, 0), $C(0, 0), $C(-w, 0));
              } else {
                throw "align: not implemented";
              }
            }
          }
        }
      }
    },
    /**
     * @param {Object} node
     * @param {number} scale
     * @return {?}
     */
    getScaledTreePosition : function(node, scale) {
      var dim = this.node;
      var w = node.getData("width");
      var h = node.getData("height");
      var route = this.config.multitree && ("$orn" in node.data && node.data.$orn) || this.config.orientation;
      /**
       * @param {number} mayParseLabeledStatementInstead
       * @param {number} recurring
       * @return {?}
       */
      var $C = function(mayParseLabeledStatementInstead, recurring) {
        return function() {
          return node.pos.add(new Vector(mayParseLabeledStatementInstead, recurring)).$scale(1 - scale);
        };
      };
      if (dim.align == "left") {
        return this.dispatch(route, $C(0, h), $C(0, 0), $C(0, 0), $C(w, 0));
      } else {
        if (dim.align == "center") {
          return this.dispatch(route, $C(0, h / 2), $C(-w / 2, 0), $C(0, -h / 2), $C(w / 2, 0));
        } else {
          if (dim.align == "right") {
            return this.dispatch(route, $C(0, 0), $C(-w, 0), $C(0, -h), $C(0, 0));
          } else {
            throw "align: not implemented";
          }
        }
      }
    },
    /**
     * @param {Object} node
     * @param {?} canvas
     * @param {number} level
     * @return {?}
     */
    treeFitsInCanvas : function(node, canvas, level) {
      var csize = canvas.getSize();
      var s = this.config.multitree && ("$orn" in node.data && node.data.$orn) || this.config.orientation;
      var size = this.dispatch(s, csize.width, csize.height);
      var baseSize = this.getTreeBaseSize(node, level, function(deepDataAndEvents, dataAndEvents) {
        return deepDataAndEvents === 0 || !dataAndEvents.anySubnode();
      });
      return baseSize < size;
    }
  });
  $jit.ST.Plot = new Class({
    Implements : Graph.Plot,
    /**
     * @param {Object} node
     * @param {Object} opt
     * @param {number} scale
     * @param {boolean} animating
     * @return {undefined}
     */
    plotSubtree : function(node, opt, scale, animating) {
      var viz = this.viz;
      var canvas = viz.canvas;
      var config = viz.config;
      /** @type {number} */
      scale = Math.min(Math.max(0.001, scale), 1);
      if (scale >= 0) {
        /** @type {boolean} */
        node.drawn = false;
        var ctx = canvas.getCtx();
        var diff = viz.geom.getScaledTreePosition(node, scale);
        ctx.translate(diff.x, diff.y);
        ctx.scale(scale, scale);
      }
      this.plotTree(node, $.merge(opt, {
        withLabels : true,
        hideLabels : !!scale,
        /**
         * @param {?} dataAndEvents
         * @param {Object} x
         * @return {?}
         */
        plotSubtree : function(dataAndEvents, x) {
          var root = config.multitree && !("$orn" in node.data);
          var orns = root && node.getData("orns");
          return!root || orns.indexOf(node.getData("orn")) > -1;
        }
      }), animating);
      if (scale >= 0) {
        /** @type {boolean} */
        node.drawn = true;
      }
    },
    /**
     * @param {?} pos
     * @param {number} width
     * @param {number} height
     * @return {?}
     */
    getAlignedPos : function(pos, width, height) {
      var dim = this.node;
      var square;
      var orn;
      if (dim.align == "center") {
        square = {
          x : pos.x - width / 2,
          y : pos.y - height / 2
        };
      } else {
        if (dim.align == "left") {
          orn = this.config.orientation;
          if (orn == "bottom" || orn == "top") {
            square = {
              x : pos.x - width / 2,
              y : pos.y
            };
          } else {
            square = {
              x : pos.x,
              y : pos.y - height / 2
            };
          }
        } else {
          if (dim.align == "right") {
            orn = this.config.orientation;
            if (orn == "bottom" || orn == "top") {
              square = {
                x : pos.x - width / 2,
                y : pos.y - height
              };
            } else {
              square = {
                x : pos.x - width,
                y : pos.y - height / 2
              };
            }
          } else {
            throw "align: not implemented";
          }
        }
      }
      return square;
    },
    /**
     * @param {?} adj
     * @return {?}
     */
    getOrientation : function(adj) {
      var config = this.config;
      var orn = config.orientation;
      if (config.multitree) {
        var nodeFrom = adj.nodeFrom;
        var nodeTo = adj.nodeTo;
        orn = "$orn" in nodeFrom.data && nodeFrom.data.$orn || "$orn" in nodeTo.data && nodeTo.data.$orn;
      }
      return orn;
    }
  });
  $jit.ST.Label = {};
  $jit.ST.Label.Native = new Class({
    Implements : Graph.Label.Native,
    /**
     * @param {?} canvas
     * @param {Object} node
     * @param {?} opt
     * @return {undefined}
     */
    renderLabel : function(canvas, node, opt) {
      var ctx = canvas.getCtx();
      var coord = node.pos.getc(true);
      var width = node.getData("width");
      var height = node.getData("height");
      var pos = this.viz.fx.getAlignedPos(coord, width, height);
      ctx.fillText(node.name, pos.x + width / 2, pos.y + height / 2);
    }
  });
  $jit.ST.Label.DOM = new Class({
    Implements : Graph.Label.DOM,
    /**
     * @param {?} from
     * @param {?} lab
     * @param {?} options
     * @return {undefined}
     */
    placeLabel : function(from, lab, options) {
      var pos = lab.pos.getc(true);
      var config = this.viz.config;
      var dim = config.Node;
      var canvas = this.viz.canvas;
      var w = lab.getData("width");
      var h = lab.getData("height");
      var $cont = canvas.getSize();
      var labelPos;
      var orn;
      var ox = canvas.translateOffsetX;
      var oy = canvas.translateOffsetY;
      var sx = canvas.scaleOffsetX;
      var sy = canvas.scaleOffsetY;
      var posx = pos.x * sx + ox;
      var posy = pos.y * sy + oy;
      if (dim.align == "center") {
        labelPos = {
          x : Math.round(posx - w / 2 + $cont.width / 2),
          y : Math.round(posy - h / 2 + $cont.height / 2)
        };
      } else {
        if (dim.align == "left") {
          orn = config.orientation;
          if (orn == "bottom" || orn == "top") {
            labelPos = {
              x : Math.round(posx - w / 2 + $cont.width / 2),
              y : Math.round(posy + $cont.height / 2)
            };
          } else {
            labelPos = {
              x : Math.round(posx + $cont.width / 2),
              y : Math.round(posy - h / 2 + $cont.height / 2)
            };
          }
        } else {
          if (dim.align == "right") {
            orn = config.orientation;
            if (orn == "bottom" || orn == "top") {
              labelPos = {
                x : Math.round(posx - w / 2 + $cont.width / 2),
                y : Math.round(posy - h + $cont.height / 2)
              };
            } else {
              labelPos = {
                x : Math.round(posx - w + $cont.width / 2),
                y : Math.round(posy - h / 2 + $cont.height / 2)
              };
            }
          } else {
            throw "align: not implemented";
          }
        }
      }
      var style = from.style;
      /** @type {string} */
      style.left = labelPos.x + "px";
      /** @type {string} */
      style.top = labelPos.y + "px";
      /** @type {string} */
      style.display = this.fitsInCanvas(labelPos, canvas) ? "" : "none";
      options.onPlaceLabel(from, lab);
    }
  });
  $jit.ST.Label.SVG = new Class({
    Implements : [$jit.ST.Label.DOM, Graph.Label.SVG],
    /**
     * @param {?} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.viz = viz;
    }
  });
  $jit.ST.Label.HTML = new Class({
    Implements : [$jit.ST.Label.DOM, Graph.Label.HTML],
    /**
     * @param {?} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.viz = viz;
    }
  });
  $jit.ST.Plot.NodeTypes = new Class({
    none : {
      /** @type {function (): undefined} */
      render : $.empty,
      contains : $.lambda(false)
    },
    circle : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @return {undefined}
       */
      render : function(adj, lab) {
        var dim = adj.getData("dim");
        var pos = this.getAlignedPos(adj.pos.getc(true), dim, dim);
        /** @type {number} */
        var qualifier = dim / 2;
        this.nodeHelper.circle.render("fill", {
          x : pos.x + qualifier,
          y : pos.y + qualifier
        }, qualifier, lab);
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {undefined}
       */
      contains : function(opt_attributes, value) {
        var dim = opt_attributes.getData("dim");
        var pos = this.getAlignedPos(opt_attributes.pos.getc(true), dim, dim);
        /** @type {number} */
        var actual = dim / 2;
        this.nodeHelper.circle.contains({
          x : pos.x + actual,
          y : pos.y + actual
        }, value, actual);
      }
    },
    square : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @return {undefined}
       */
      render : function(adj, lab) {
        var dim = adj.getData("dim");
        /** @type {number} */
        var qualifier = dim / 2;
        var pos = this.getAlignedPos(adj.pos.getc(true), dim, dim);
        this.nodeHelper.square.render("fill", {
          x : pos.x + qualifier,
          y : pos.y + qualifier
        }, qualifier, lab);
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {undefined}
       */
      contains : function(opt_attributes, value) {
        var dim = opt_attributes.getData("dim");
        var pos = this.getAlignedPos(opt_attributes.pos.getc(true), dim, dim);
        /** @type {number} */
        var actual = dim / 2;
        this.nodeHelper.square.contains({
          x : pos.x + actual,
          y : pos.y + actual
        }, value, actual);
      }
    },
    ellipse : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @return {undefined}
       */
      render : function(adj, lab) {
        var qualifier = adj.getData("width");
        var cycle = adj.getData("height");
        var pos = this.getAlignedPos(adj.pos.getc(true), qualifier, cycle);
        this.nodeHelper.ellipse.render("fill", {
          x : pos.x + qualifier / 2,
          y : pos.y + cycle / 2
        }, qualifier, cycle, lab);
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {undefined}
       */
      contains : function(opt_attributes, value) {
        var actual = opt_attributes.getData("width");
        var epsilon = opt_attributes.getData("height");
        var pos = this.getAlignedPos(opt_attributes.pos.getc(true), actual, epsilon);
        this.nodeHelper.ellipse.contains({
          x : pos.x + actual / 2,
          y : pos.y + epsilon / 2
        }, value, actual, epsilon);
      }
    },
    rectangle : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @return {undefined}
       */
      render : function(adj, lab) {
        var qualifier = adj.getData("width");
        var cycle = adj.getData("height");
        var pos = this.getAlignedPos(adj.pos.getc(true), qualifier, cycle);
        this.nodeHelper.rectangle.render("fill", {
          x : pos.x + qualifier / 2,
          y : pos.y + cycle / 2
        }, qualifier, cycle, lab);
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {undefined}
       */
      contains : function(opt_attributes, value) {
        var actual = opt_attributes.getData("width");
        var epsilon = opt_attributes.getData("height");
        var pos = this.getAlignedPos(opt_attributes.pos.getc(true), actual, epsilon);
        this.nodeHelper.rectangle.contains({
          x : pos.x + actual / 2,
          y : pos.y + epsilon / 2
        }, value, actual, epsilon);
      }
    }
  });
  $jit.ST.Plot.EdgeTypes = new Class({
    /** @type {function (): undefined} */
    none : $.empty,
    line : {
      /**
       * @param {?} adj
       * @param {?} type
       * @return {undefined}
       */
      render : function(adj, type) {
        var orn = this.getOrientation(adj);
        var nodeFrom = adj.nodeFrom;
        var nodeTo = adj.nodeTo;
        /** @type {boolean} */
        var rel = nodeFrom._depth < nodeTo._depth;
        var from = this.viz.geom.getEdge(rel ? nodeFrom : nodeTo, "begin", orn);
        var lab = this.viz.geom.getEdge(rel ? nodeTo : nodeFrom, "end", orn);
        this.edgeHelper.line.render(from, lab, type);
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {?}
       */
      contains : function(opt_attributes, value) {
        var orn = this.getOrientation(opt_attributes);
        var nodeFrom = opt_attributes.nodeFrom;
        var nodeTo = opt_attributes.nodeTo;
        /** @type {boolean} */
        var rel = nodeFrom._depth < nodeTo._depth;
        var attributes = this.viz.geom.getEdge(rel ? nodeFrom : nodeTo, "begin", orn);
        var pdataOld = this.viz.geom.getEdge(rel ? nodeTo : nodeFrom, "end", orn);
        return this.edgeHelper.line.contains(attributes, pdataOld, value, this.edge.epsilon);
      }
    },
    arrow : {
      /**
       * @param {?} adj
       * @param {?} type
       * @return {undefined}
       */
      render : function(adj, type) {
        var orn = this.getOrientation(adj);
        var node = adj.nodeFrom;
        var child = adj.nodeTo;
        var qualifier = adj.getData("dim");
        var from = this.viz.geom.getEdge(node, "begin", orn);
        var lab = this.viz.geom.getEdge(child, "end", orn);
        var direction = adj.data.$direction;
        var cycle = direction && (direction.length > 1 && direction[0] != node.id);
        this.edgeHelper.arrow.render(from, lab, qualifier, cycle, type);
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {?}
       */
      contains : function(opt_attributes, value) {
        var orn = this.getOrientation(opt_attributes);
        var nodeFrom = opt_attributes.nodeFrom;
        var nodeTo = opt_attributes.nodeTo;
        /** @type {boolean} */
        var rel = nodeFrom._depth < nodeTo._depth;
        var attributes = this.viz.geom.getEdge(rel ? nodeFrom : nodeTo, "begin", orn);
        var pdataOld = this.viz.geom.getEdge(rel ? nodeTo : nodeFrom, "end", orn);
        return this.edgeHelper.arrow.contains(attributes, pdataOld, value, this.edge.epsilon);
      }
    },
    "quadratic:begin" : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @return {undefined}
       */
      render : function(adj, lab) {
        var orn = this.getOrientation(adj);
        var nodeFrom = adj.nodeFrom;
        var nodeTo = adj.nodeTo;
        /** @type {boolean} */
        var rel = nodeFrom._depth < nodeTo._depth;
        var begin = this.viz.geom.getEdge(rel ? nodeFrom : nodeTo, "begin", orn);
        var end = this.viz.geom.getEdge(rel ? nodeTo : nodeFrom, "end", orn);
        var dim = adj.getData("dim");
        var ctx = lab.getCtx();
        ctx.beginPath();
        ctx.moveTo(begin.x, begin.y);
        switch(orn) {
          case "left":
            ctx.quadraticCurveTo(begin.x + dim, begin.y, end.x, end.y);
            break;
          case "right":
            ctx.quadraticCurveTo(begin.x - dim, begin.y, end.x, end.y);
            break;
          case "top":
            ctx.quadraticCurveTo(begin.x, begin.y + dim, end.x, end.y);
            break;
          case "bottom":
            ctx.quadraticCurveTo(begin.x, begin.y - dim, end.x, end.y);
            break;
        }
        ctx.stroke();
      }
    },
    "quadratic:end" : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @return {undefined}
       */
      render : function(adj, lab) {
        var orn = this.getOrientation(adj);
        var nodeFrom = adj.nodeFrom;
        var nodeTo = adj.nodeTo;
        /** @type {boolean} */
        var rel = nodeFrom._depth < nodeTo._depth;
        var begin = this.viz.geom.getEdge(rel ? nodeFrom : nodeTo, "begin", orn);
        var end = this.viz.geom.getEdge(rel ? nodeTo : nodeFrom, "end", orn);
        var dim = adj.getData("dim");
        var ctx = lab.getCtx();
        ctx.beginPath();
        ctx.moveTo(begin.x, begin.y);
        switch(orn) {
          case "left":
            ctx.quadraticCurveTo(end.x - dim, end.y, end.x, end.y);
            break;
          case "right":
            ctx.quadraticCurveTo(end.x + dim, end.y, end.x, end.y);
            break;
          case "top":
            ctx.quadraticCurveTo(end.x, end.y - dim, end.x, end.y);
            break;
          case "bottom":
            ctx.quadraticCurveTo(end.x, end.y + dim, end.x, end.y);
            break;
        }
        ctx.stroke();
      }
    },
    bezier : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @return {undefined}
       */
      render : function(adj, lab) {
        var orn = this.getOrientation(adj);
        var nodeFrom = adj.nodeFrom;
        var nodeTo = adj.nodeTo;
        /** @type {boolean} */
        var rel = nodeFrom._depth < nodeTo._depth;
        var begin = this.viz.geom.getEdge(rel ? nodeFrom : nodeTo, "begin", orn);
        var end = this.viz.geom.getEdge(rel ? nodeTo : nodeFrom, "end", orn);
        var dim = adj.getData("dim");
        var ctx = lab.getCtx();
        ctx.beginPath();
        ctx.moveTo(begin.x, begin.y);
        switch(orn) {
          case "left":
            ctx.bezierCurveTo(begin.x + dim, begin.y, end.x - dim, end.y, end.x, end.y);
            break;
          case "right":
            ctx.bezierCurveTo(begin.x - dim, begin.y, end.x + dim, end.y, end.x, end.y);
            break;
          case "top":
            ctx.bezierCurveTo(begin.x, begin.y + dim, end.x, end.y - dim, end.x, end.y);
            break;
          case "bottom":
            ctx.bezierCurveTo(begin.x, begin.y - dim, end.x, end.y + dim, end.x, end.y);
            break;
        }
        ctx.stroke();
      }
    }
  });
  $jit.ST.Plot.NodeTypes.implement({
    "areachart-stacked" : {
      /**
       * @param {?} node
       * @param {?} lab
       * @return {undefined}
       */
      render : function(node, lab) {
        var pos = node.pos.getc(true);
        var width = node.getData("width");
        var height = node.getData("height");
        var algnPos = this.getAlignedPos(pos, width, height);
        var x = algnPos.x;
        var y = algnPos.y;
        var stringArray = node.getData("stringArray");
        var dimArray = node.getData("dimArray");
        var valArray = node.getData("valueArray");
        var valLeft = $.reduce(valArray, function(dataAndEvents, deepDataAndEvents) {
          return dataAndEvents + deepDataAndEvents[0];
        }, 0);
        var valRight = $.reduce(valArray, function(dataAndEvents, deepDataAndEvents) {
          return dataAndEvents + deepDataAndEvents[1];
        }, 0);
        var colorArray = node.getData("colorArray");
        var colorLength = colorArray.length;
        var config = node.getData("config");
        var gradient = node.getData("gradient");
        var showLabels = config.showLabels;
        var aggregates = config.showAggregates;
        var label = config.Label;
        var prev = node.getData("prev");
        var ctx = lab.getCtx();
        var border = node.getData("border");
        if (colorArray && (dimArray && stringArray)) {
          /** @type {number} */
          var i = 0;
          var l = dimArray.length;
          /** @type {number} */
          var acumLeft = 0;
          /** @type {number} */
          var acumRight = 0;
          /** @type {number} */
          var valAcum = 0;
          for (;i < l;i++) {
            ctx.fillStyle = ctx.strokeStyle = colorArray[i % colorLength];
            ctx.save();
            if (gradient && (dimArray[i][0] > 0 || dimArray[i][1] > 0)) {
              var h1 = acumLeft + dimArray[i][0];
              var h2 = acumRight + dimArray[i][1];
              /** @type {number} */
              var theta2 = Math.atan((h2 - h1) / width);
              /** @type {number} */
              var delta = 55;
              var linear = ctx.createLinearGradient(x + width / 2, y - (h1 + h2) / 2, x + width / 2 + delta * Math.sin(theta2), y - (h1 + h2) / 2 + delta * Math.cos(theta2));
              var color = $.rgbToHex($.map($.hexToRgb(colorArray[i % colorLength].slice(1)), function(dataAndEvents) {
                return dataAndEvents * 0.85 >> 0;
              }));
              linear.addColorStop(0, colorArray[i % colorLength]);
              linear.addColorStop(1, color);
              ctx.fillStyle = linear;
            }
            ctx.beginPath();
            ctx.moveTo(x, y - acumLeft);
            ctx.lineTo(x + width, y - acumRight);
            ctx.lineTo(x + width, y - acumRight - dimArray[i][1]);
            ctx.lineTo(x, y - acumLeft - dimArray[i][0]);
            ctx.lineTo(x, y - acumLeft);
            ctx.fill();
            ctx.restore();
            if (border) {
              /** @type {boolean} */
              var strong = border.name == stringArray[i];
              /** @type {number} */
              var b1 = strong ? 0.7 : 0.8;
              color = $.rgbToHex($.map($.hexToRgb(colorArray[i % colorLength].slice(1)), function(a4) {
                return a4 * b1 >> 0;
              }));
              ctx.strokeStyle = color;
              /** @type {number} */
              ctx.lineWidth = strong ? 4 : 1;
              ctx.save();
              ctx.beginPath();
              if (border.index === 0) {
                ctx.moveTo(x, y - acumLeft);
                ctx.lineTo(x, y - acumLeft - dimArray[i][0]);
              } else {
                ctx.moveTo(x + width, y - acumRight);
                ctx.lineTo(x + width, y - acumRight - dimArray[i][1]);
              }
              ctx.stroke();
              ctx.restore();
            }
            acumLeft += dimArray[i][0] || 0;
            acumRight += dimArray[i][1] || 0;
            if (dimArray[i][0] > 0) {
              valAcum += valArray[i][0] || 0;
            }
          }
          if (prev && label.type == "Native") {
            ctx.save();
            ctx.beginPath();
            ctx.fillStyle = ctx.strokeStyle = label.color;
            /** @type {string} */
            ctx.font = label.style + " " + label.size + "px " + label.family;
            /** @type {string} */
            ctx.textAlign = "center";
            /** @type {string} */
            ctx.textBaseline = "middle";
            var aggValue = aggregates(node.name, valLeft, valRight, node, valAcum);
            if (aggValue !== false) {
              ctx.fillText(aggValue !== true ? aggValue : valAcum, x, y - acumLeft - config.labelOffset - label.size / 2, width);
            }
            if (showLabels(node.name, valLeft, valRight, node)) {
              ctx.fillText(node.name, x, y + label.size / 2 + config.labelOffset);
            }
            ctx.restore();
          }
        }
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {?}
       */
      contains : function(opt_attributes, value) {
        var pos = opt_attributes.pos.getc(true);
        var width = opt_attributes.getData("width");
        var height = opt_attributes.getData("height");
        var algnPos = this.getAlignedPos(pos, width, height);
        var x = algnPos.x;
        var y = algnPos.y;
        var dimArray = opt_attributes.getData("dimArray");
        /** @type {number} */
        var rx = value.x - x;
        if (value.x < x || (value.x > x + width || (value.y > y || value.y < y - height))) {
          return false;
        }
        /** @type {number} */
        var i = 0;
        var l = dimArray.length;
        var lAcum = y;
        var rAcum = y;
        for (;i < l;i++) {
          var dimi = dimArray[i];
          lAcum -= dimi[0];
          rAcum -= dimi[1];
          var intersec = lAcum + (rAcum - lAcum) * rx / width;
          if (value.y >= intersec) {
            /** @type {number} */
            var j = +(rx > width / 2);
            return{
              name : opt_attributes.getData("stringArray")[i],
              color : opt_attributes.getData("colorArray")[i],
              value : opt_attributes.getData("valueArray")[i][j],
              index : j
            };
          }
        }
        return false;
      }
    }
  });
  $jit.AreaChart = new Class({
    st : null,
    colors : ["#416D9C", "#70A35E", "#EBB056", "#C74243", "#83548B", "#909291", "#557EAA"],
    selected : {},
    busy : false,
    /**
     * @param {?} controller
     * @return {undefined}
     */
    initialize : function(controller) {
      this.controller = this.config = $.merge(Options("Canvas", "Margin", "Label", "AreaChart"), {
        Label : {
          type : "Native"
        }
      }, controller);
      var showLabels = this.config.showLabels;
      var typeLabels = $.type(showLabels);
      var showAggregates = this.config.showAggregates;
      var typeAggregates = $.type(showAggregates);
      this.config.showLabels = typeLabels == "function" ? showLabels : $.lambda(showLabels);
      this.config.showAggregates = typeAggregates == "function" ? showAggregates : $.lambda(showAggregates);
      this.initializeViz();
    },
    /**
     * @return {undefined}
     */
    initializeViz : function() {
      var config = this.config;
      var that = this;
      var nodeType = config.type.split(":")[0];
      var nodeLabels = {};
      var delegate = new $jit.ST({
        injectInto : config.injectInto,
        width : config.width,
        height : config.height,
        orientation : "bottom",
        levelDistance : 0,
        siblingOffset : 0,
        subtreeOffset : 0,
        withLabels : config.Label.type != "Native",
        useCanvas : config.useCanvas,
        Label : {
          type : config.Label.type
        },
        Node : {
          overridable : true,
          type : "areachart-" + nodeType,
          align : "left",
          width : 1,
          height : 1
        },
        Edge : {
          type : "none"
        },
        Tips : {
          enable : config.Tips.enable,
          type : "Native",
          force : true,
          /**
           * @param {?} from
           * @param {?} type
           * @param {?} event
           * @return {undefined}
           */
          onShow : function(from, type, event) {
            var lab = event;
            config.Tips.onShow(from, lab, type);
          }
        },
        Events : {
          enable : true,
          type : "Native",
          /**
           * @param {?} adj
           * @param {?} lab
           * @param {?} selector
           * @return {undefined}
           */
          onClick : function(adj, lab, selector) {
            if (!config.filterOnClick && !config.Events.enable) {
              return;
            }
            var from = lab.getContains();
            if (from) {
              if (config.filterOnClick) {
                that.filter(from.name);
              }
            }
            if (config.Events.enable) {
              config.Events.onClick(from, lab, selector);
            }
          },
          /**
           * @param {?} adj
           * @param {?} lab
           * @param {?} event
           * @return {undefined}
           */
          onRightClick : function(adj, lab, event) {
            if (!config.restoreOnRightClick) {
              return;
            }
            that.restore();
          },
          /**
           * @param {?} adj
           * @param {?} lab
           * @param {?} event
           * @return {undefined}
           */
          onMouseMove : function(adj, lab, event) {
            if (!config.selectOnHover) {
              return;
            }
            if (adj) {
              var elem = lab.getContains();
              that.select(adj.id, elem.name, elem.index);
            } else {
              that.select(false, false, false);
            }
          }
        },
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        onCreateLabel : function(adj, lab) {
          var labelConf = config.Label;
          var valueArray = lab.getData("valueArray");
          var acumLeft = $.reduce(valueArray, function(dataAndEvents, deepDataAndEvents) {
            return dataAndEvents + deepDataAndEvents[0];
          }, 0);
          var acumRight = $.reduce(valueArray, function(dataAndEvents, deepDataAndEvents) {
            return dataAndEvents + deepDataAndEvents[1];
          }, 0);
          if (lab.getData("prev")) {
            var nlbs = {
              wrapper : document.createElement("div"),
              aggregate : document.createElement("div"),
              label : document.createElement("div")
            };
            /** @type {Element} */
            var wrapper = nlbs.wrapper;
            /** @type {Element} */
            var label = nlbs.label;
            /** @type {Element} */
            var aggregate = nlbs.aggregate;
            /** @type {(CSSStyleDeclaration|null)} */
            var wrapperStyle = wrapper.style;
            /** @type {(CSSStyleDeclaration|null)} */
            var style = label.style;
            /** @type {(CSSStyleDeclaration|null)} */
            var aggregateStyle = aggregate.style;
            nodeLabels[lab.id] = nlbs;
            wrapper.appendChild(label);
            wrapper.appendChild(aggregate);
            if (!config.showLabels(lab.name, acumLeft, acumRight, lab)) {
              /** @type {string} */
              label.style.display = "none";
            }
            if (!config.showAggregates(lab.name, acumLeft, acumRight, lab)) {
              /** @type {string} */
              aggregate.style.display = "none";
            }
            /** @type {string} */
            wrapperStyle.position = "relative";
            /** @type {string} */
            wrapperStyle.overflow = "visible";
            /** @type {string} */
            wrapperStyle.fontSize = labelConf.size + "px";
            wrapperStyle.fontFamily = labelConf.family;
            wrapperStyle.color = labelConf.color;
            /** @type {string} */
            wrapperStyle.textAlign = "center";
            /** @type {string} */
            aggregateStyle.position = style.position = "absolute";
            adj.style.width = lab.getData("width") + "px";
            adj.style.height = lab.getData("height") + "px";
            label.innerHTML = lab.name;
            adj.appendChild(wrapper);
          }
        },
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        onPlaceLabel : function(adj, lab) {
          if (!lab.getData("prev")) {
            return;
          }
          var labels = nodeLabels[lab.id];
          var wrapperStyle = labels.wrapper.style;
          var aggregateStyle = labels.label.style;
          var style = labels.aggregate.style;
          var w = lab.getData("width");
          var constrainedHeight = lab.getData("height");
          var dimArray = lab.getData("dimArray");
          var valArray = lab.getData("valueArray");
          var acumLeft = $.reduce(valArray, function(dataAndEvents, deepDataAndEvents) {
            return dataAndEvents + deepDataAndEvents[0];
          }, 0);
          var acumRight = $.reduce(valArray, function(dataAndEvents, deepDataAndEvents) {
            return dataAndEvents + deepDataAndEvents[1];
          }, 0);
          /** @type {number} */
          var font = parseInt(wrapperStyle.fontSize, 10);
          var styleDeclaration = adj.style;
          if (dimArray && valArray) {
            if (config.showLabels(lab.name, acumLeft, acumRight, lab)) {
              /** @type {string} */
              aggregateStyle.display = "";
            } else {
              /** @type {string} */
              aggregateStyle.display = "none";
            }
            var aggValue = config.showAggregates(lab.name, acumLeft, acumRight, lab);
            if (aggValue !== false) {
              /** @type {string} */
              style.display = "";
            } else {
              /** @type {string} */
              style.display = "none";
            }
            /** @type {string} */
            wrapperStyle.width = style.width = aggregateStyle.width = adj.style.width = w + "px";
            /** @type {string} */
            style.left = aggregateStyle.left = -w / 2 + "px";
            /** @type {number} */
            var i = 0;
            var l = valArray.length;
            /** @type {number} */
            var acum = 0;
            /** @type {number} */
            var leftAcum = 0;
            for (;i < l;i++) {
              if (dimArray[i][0] > 0) {
                acum += valArray[i][0];
                leftAcum += dimArray[i][0];
              }
            }
            /** @type {string} */
            style.top = -font - config.labelOffset + "px";
            /** @type {string} */
            aggregateStyle.top = config.labelOffset + leftAcum + "px";
            /** @type {string} */
            adj.style.top = parseInt(adj.style.top, 10) - leftAcum + "px";
            /** @type {string} */
            adj.style.height = wrapperStyle.height = leftAcum + "px";
            labels.aggregate.innerHTML = aggValue !== true ? aggValue : acum;
          }
        }
      });
      var testNode = delegate.canvas.getSize();
      var margin = config.Margin;
      delegate.config.offsetY = -testNode.height / 2 + margin.bottom + (config.showLabels && config.labelOffset + config.Label.size);
      /** @type {number} */
      delegate.config.offsetX = (margin.right - margin.left) / 2;
      this.delegate = delegate;
      this.canvas = this.delegate.canvas;
    },
    /**
     * @param {Object} json
     * @return {undefined}
     */
    loadJSON : function(json) {
      /** @type {number} */
      var prefix = $.time();
      /** @type {Array} */
      var ch = [];
      var delegate = this.delegate;
      var name = $.splat(json.label);
      var color = $.splat(json.color || this.colors);
      var config = this.config;
      /** @type {boolean} */
      var gradient = !!config.type.split(":")[1];
      var animate = config.animate;
      /** @type {number} */
      var i = 0;
      var values = json.values;
      var valuesLen = values.length;
      for (;i < valuesLen - 1;i++) {
        var value = values[i];
        var prev = values[i - 1];
        var next = values[i + 1];
        var valLeft = $.splat(values[i].values);
        var valRight = $.splat(values[i + 1].values);
        var valArray = $.zip(valLeft, valRight);
        /** @type {number} */
        var D = 0;
        /** @type {number} */
        var C = 0;
        ch.push({
          id : prefix + value.label,
          name : value.label,
          data : {
            value : valArray,
            "$valueArray" : valArray,
            "$colorArray" : color,
            "$stringArray" : name,
            "$next" : next.label,
            "$prev" : prev ? prev.label : false,
            "$config" : config,
            "$gradient" : gradient
          },
          children : []
        });
      }
      var root = {
        id : prefix + "$root",
        name : "",
        data : {
          "$type" : "none",
          "$width" : 1,
          "$height" : 1
        },
        children : ch
      };
      delegate.loadJSON(root);
      this.normalizeDims();
      delegate.compute();
      delegate.select(delegate.root);
      if (animate) {
        delegate.fx.animate({
          modes : ["node-property:height:dimArray"],
          duration : 1500
        });
      }
    },
    /**
     * @param {Object} json
     * @param {Object} onComplete
     * @return {undefined}
     */
    updateJSON : function(json, onComplete) {
      if (this.busy) {
        return;
      }
      /** @type {boolean} */
      this.busy = true;
      var delegate = this.delegate;
      var graph = delegate.graph;
      var extended = json.label && $.splat(json.label);
      var values = json.values;
      var animate = this.config.animate;
      var that = this;
      var hashValues = {};
      /** @type {number} */
      var i = 0;
      var valuesLen = values.length;
      for (;i < valuesLen;i++) {
        hashValues[values[i].label] = values[i];
      }
      graph.eachNode(function(n) {
        var v = hashValues[n.name];
        var original = n.getData("stringArray");
        var attributes = n.getData("valueArray");
        var next = n.getData("next");
        if (v) {
          v.values = $.splat(v.values);
          $.each(attributes, function(a, key) {
            a[0] = v.values[key];
            if (extended) {
              original[key] = extended[key];
            }
          });
          n.setData("valueArray", attributes);
        }
        if (next) {
          v = hashValues[next];
          if (v) {
            $.each(attributes, function(vec, i) {
              vec[1] = v.values[i];
            });
          }
        }
      });
      this.normalizeDims();
      delegate.compute();
      delegate.select(delegate.root);
      if (animate) {
        delegate.fx.animate({
          modes : ["node-property:height:dimArray"],
          duration : 1500,
          /**
           * @return {undefined}
           */
          onComplete : function() {
            /** @type {boolean} */
            that.busy = false;
            if (onComplete) {
              onComplete.onComplete();
            }
          }
        });
      }
    },
    /**
     * @param {string} flags
     * @param {Object} scope
     * @return {undefined}
     */
    filter : function(flags, scope) {
      if (this.busy) {
        return;
      }
      /** @type {boolean} */
      this.busy = true;
      if (this.config.Tips.enable) {
        this.delegate.tips.hide();
      }
      this.select(false, false, false);
      var filter = $.splat(flags);
      var root = this.delegate.graph.getNode(this.delegate.root);
      var that = this;
      this.normalizeDims();
      root.eachAdjacency(function(adj) {
        var n = adj.nodeTo;
        var dimArray = n.getData("dimArray", "end");
        var stringArray = n.getData("stringArray");
        n.setData("dimArray", $.map(dimArray, function(dataAndEvents, i) {
          return $.indexOf(filter, stringArray[i]) > -1 ? dataAndEvents : [0, 0];
        }), "end");
      });
      this.delegate.fx.animate({
        modes : ["node-property:dimArray"],
        duration : 1500,
        /**
         * @return {undefined}
         */
        onComplete : function() {
          /** @type {boolean} */
          that.busy = false;
          if (scope) {
            scope.onComplete();
          }
        }
      });
    },
    /**
     * @param {Object} callback
     * @return {undefined}
     */
    restore : function(callback) {
      if (this.busy) {
        return;
      }
      /** @type {boolean} */
      this.busy = true;
      if (this.config.Tips.enable) {
        this.delegate.tips.hide();
      }
      this.select(false, false, false);
      this.normalizeDims();
      var that = this;
      this.delegate.fx.animate({
        modes : ["node-property:height:dimArray"],
        duration : 1500,
        /**
         * @return {undefined}
         */
        onComplete : function() {
          /** @type {boolean} */
          that.busy = false;
          if (callback) {
            callback.onComplete();
          }
        }
      });
    },
    /**
     * @param {?} id
     * @param {boolean} lab
     * @param {boolean} index
     * @return {undefined}
     */
    select : function(id, lab, index) {
      if (!this.config.selectOnHover) {
        return;
      }
      var s = this.selected;
      if (s.id != id || (s.name != lab || s.index != index)) {
        s.id = id;
        /** @type {boolean} */
        s.name = lab;
        /** @type {boolean} */
        s.index = index;
        this.delegate.graph.eachNode(function(n) {
          n.setData("border", false);
        });
        if (id) {
          var n = this.delegate.graph.getNode(id);
          n.setData("border", s);
          /** @type {string} */
          var link = index === 0 ? "prev" : "next";
          link = n.getData(link);
          if (link) {
            n = this.delegate.graph.getByName(link);
            if (n) {
              n.setData("border", {
                name : lab,
                index : 1 - index
              });
            }
          }
        }
        this.delegate.plot();
      }
    },
    /**
     * @return {?}
     */
    getLegend : function() {
      var legend = {};
      var n;
      this.delegate.graph.getNode(this.delegate.root).eachAdjacency(function(adj) {
        n = adj.nodeTo;
      });
      var colors = n.getData("colorArray");
      var colorsLen = colors.length;
      $.each(n.getData("stringArray"), function(s, i) {
        legend[s] = colors[i % colorsLen];
      });
      return legend;
    },
    /**
     * @return {?}
     */
    getMaxValue : function() {
      /** @type {number} */
      var maxValue = 0;
      this.delegate.graph.eachNode(function(n) {
        var attributes = n.getData("valueArray");
        /** @type {number} */
        var y = 0;
        /** @type {number} */
        var x = 0;
        $.each(attributes, function(dataAndEvents) {
          y += +dataAndEvents[0];
          x += +dataAndEvents[1];
        });
        var acum = x > y ? x : y;
        maxValue = maxValue > acum ? maxValue : acum;
      });
      return maxValue;
    },
    /**
     * @return {undefined}
     */
    normalizeDims : function() {
      var root = this.delegate.graph.getNode(this.delegate.root);
      /** @type {number} */
      var z = 0;
      root.eachAdjacency(function() {
        z++;
      });
      var maxValue = this.getMaxValue() || 1;
      var $cont = this.delegate.canvas.getSize();
      var config = this.config;
      var margin = config.Margin;
      var labelOffset = config.labelOffset + config.Label.size;
      /** @type {number} */
      var recurring = ($cont.width - (margin.left + margin.right)) / z;
      var animate = config.animate;
      /** @type {number} */
      var height = $cont.height - (margin.top + margin.bottom) - (config.showAggregates && labelOffset) - (config.showLabels && labelOffset);
      this.delegate.graph.eachNode(function(n) {
        /** @type {number} */
        var y = 0;
        /** @type {number} */
        var x = 0;
        /** @type {Array} */
        var animateValue = [];
        $.each(n.getData("valueArray"), function(dataAndEvents) {
          y += +dataAndEvents[0];
          x += +dataAndEvents[1];
          animateValue.push([0, 0]);
        });
        var acum = x > y ? x : y;
        n.setData("width", recurring);
        if (animate) {
          n.setData("height", acum * height / maxValue, "end");
          n.setData("dimArray", $.map(n.getData("valueArray"), function(n) {
            return[n[0] * height / maxValue, n[1] * height / maxValue];
          }), "end");
          var dimArray = n.getData("dimArray");
          if (!dimArray) {
            n.setData("dimArray", animateValue);
          }
        } else {
          n.setData("height", acum * height / maxValue);
          n.setData("dimArray", $.map(n.getData("valueArray"), function(n) {
            return[n[0] * height / maxValue, n[1] * height / maxValue];
          }));
        }
      });
    }
  });
  Options.BarChart = {
    $extend : true,
    animate : true,
    type : "stacked",
    labelOffset : 3,
    barsOffset : 0,
    hoveredColor : "#9fd4ff",
    orientation : "horizontal",
    showAggregates : true,
    showLabels : true,
    Tips : {
      enable : false,
      /** @type {function (): undefined} */
      onShow : $.empty,
      /** @type {function (): undefined} */
      onHide : $.empty
    },
    Events : {
      enable : false,
      /** @type {function (): undefined} */
      onClick : $.empty
    }
  };
  $jit.ST.Plot.NodeTypes.implement({
    "barchart-stacked" : {
      /**
       * @param {?} node
       * @param {?} lab
       * @return {undefined}
       */
      render : function(node, lab) {
        var pos = node.pos.getc(true);
        var width = node.getData("width");
        var height = node.getData("height");
        var algnPos = this.getAlignedPos(pos, width, height);
        var x = algnPos.x;
        var y = algnPos.y;
        var dimArray = node.getData("dimArray");
        var valueArray = node.getData("valueArray");
        var colorArray = node.getData("colorArray");
        var colorLength = colorArray.length;
        var stringArray = node.getData("stringArray");
        var ctx = lab.getCtx();
        var opt = {};
        var border = node.getData("border");
        var gradient = node.getData("gradient");
        var config = node.getData("config");
        /** @type {boolean} */
        var isH = config.orientation == "horizontal";
        var aggregates = config.showAggregates;
        var showLabels = config.showLabels;
        var label = config.Label;
        if (colorArray && (dimArray && stringArray)) {
          /** @type {number} */
          var i = 0;
          var l = dimArray.length;
          /** @type {number} */
          var acum = 0;
          /** @type {number} */
          var valAcum = 0;
          for (;i < l;i++) {
            ctx.fillStyle = ctx.strokeStyle = colorArray[i % colorLength];
            if (gradient) {
              var linear;
              if (isH) {
                linear = ctx.createLinearGradient(x + acum + dimArray[i] / 2, y, x + acum + dimArray[i] / 2, y + height);
              } else {
                linear = ctx.createLinearGradient(x, y - acum - dimArray[i] / 2, x + width, y - acum - dimArray[i] / 2);
              }
              var color = $.rgbToHex($.map($.hexToRgb(colorArray[i % colorLength].slice(1)), function(dataAndEvents) {
                return dataAndEvents * 0.5 >> 0;
              }));
              linear.addColorStop(0, color);
              linear.addColorStop(0.5, colorArray[i % colorLength]);
              linear.addColorStop(1, color);
              ctx.fillStyle = linear;
            }
            if (isH) {
              ctx.fillRect(x + acum, y, dimArray[i], height);
            } else {
              ctx.fillRect(x, y - acum - dimArray[i], width, dimArray[i]);
            }
            if (border && border.name == stringArray[i]) {
              opt.acum = acum;
              opt.dimValue = dimArray[i];
            }
            acum += dimArray[i] || 0;
            valAcum += valueArray[i] || 0;
          }
          if (border) {
            ctx.save();
            /** @type {number} */
            ctx.lineWidth = 2;
            ctx.strokeStyle = border.color;
            if (isH) {
              ctx.strokeRect(x + opt.acum + 1, y + 1, opt.dimValue - 2, height - 2);
            } else {
              ctx.strokeRect(x + 1, y - opt.acum - opt.dimValue + 1, width - 2, opt.dimValue - 2);
            }
            ctx.restore();
          }
          if (label.type == "Native") {
            ctx.save();
            ctx.fillStyle = ctx.strokeStyle = label.color;
            /** @type {string} */
            ctx.font = label.style + " " + label.size + "px " + label.family;
            /** @type {string} */
            ctx.textBaseline = "middle";
            var aggValue = aggregates(node.name, valAcum, node);
            if (aggValue !== false) {
              aggValue = aggValue !== true ? aggValue : valAcum;
              if (isH) {
                /** @type {string} */
                ctx.textAlign = "right";
                ctx.fillText(aggValue, x + acum - config.labelOffset, y + height / 2);
              } else {
                /** @type {string} */
                ctx.textAlign = "center";
                ctx.fillText(aggValue, x + width / 2, y - height - label.size / 2 - config.labelOffset);
              }
            }
            if (showLabels(node.name, valAcum, node)) {
              if (isH) {
                /** @type {string} */
                ctx.textAlign = "center";
                ctx.translate(x - config.labelOffset - label.size / 2, y + height / 2);
                ctx.rotate(Math.PI / 2);
                ctx.fillText(node.name, 0, 0);
              } else {
                /** @type {string} */
                ctx.textAlign = "center";
                ctx.fillText(node.name, x + width / 2, y + label.size / 2 + config.labelOffset);
              }
            }
            ctx.restore();
          }
        }
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {?}
       */
      contains : function(opt_attributes, value) {
        var pos = opt_attributes.pos.getc(true);
        var width = opt_attributes.getData("width");
        var height = opt_attributes.getData("height");
        var algnPos = this.getAlignedPos(pos, width, height);
        var x = algnPos.x;
        var y = algnPos.y;
        var dimArray = opt_attributes.getData("dimArray");
        var config = opt_attributes.getData("config");
        /** @type {number} */
        var dx0 = value.x - x;
        /** @type {boolean} */
        var horz = config.orientation == "horizontal";
        if (horz) {
          if (value.x < x || (value.x > x + width || (value.y > y + height || value.y < y))) {
            return false;
          }
        } else {
          if (value.x < x || (value.x > x + width || (value.y > y || value.y < y - height))) {
            return false;
          }
        }
        /** @type {number} */
        var i = 0;
        var l = dimArray.length;
        var acum = horz ? x : y;
        for (;i < l;i++) {
          var dimi = dimArray[i];
          if (horz) {
            acum += dimi;
            var intersec = acum;
            if (value.x <= intersec) {
              return{
                name : opt_attributes.getData("stringArray")[i],
                color : opt_attributes.getData("colorArray")[i],
                value : opt_attributes.getData("valueArray")[i],
                label : opt_attributes.name
              };
            }
          } else {
            acum -= dimi;
            intersec = acum;
            if (value.y >= intersec) {
              return{
                name : opt_attributes.getData("stringArray")[i],
                color : opt_attributes.getData("colorArray")[i],
                value : opt_attributes.getData("valueArray")[i],
                label : opt_attributes.name
              };
            }
          }
        }
        return false;
      }
    },
    "barchart-grouped" : {
      /**
       * @param {?} node
       * @param {?} lab
       * @return {undefined}
       */
      render : function(node, lab) {
        var pos = node.pos.getc(true);
        var width = node.getData("width");
        var height = node.getData("height");
        var algnPos = this.getAlignedPos(pos, width, height);
        var x = algnPos.x;
        var y = algnPos.y;
        var dimArray = node.getData("dimArray");
        var valueArray = node.getData("valueArray");
        var valueLength = valueArray.length;
        var colorArray = node.getData("colorArray");
        var colorLength = colorArray.length;
        var stringArray = node.getData("stringArray");
        var ctx = lab.getCtx();
        var opt = {};
        var border = node.getData("border");
        var gradient = node.getData("gradient");
        var config = node.getData("config");
        /** @type {boolean} */
        var horz = config.orientation == "horizontal";
        var aggregates = config.showAggregates;
        var showLabels = config.showLabels;
        var label = config.Label;
        /** @type {number} */
        var fixedDim = (horz ? height : width) / valueLength;
        if (colorArray && (dimArray && stringArray)) {
          /** @type {number} */
          var i = 0;
          var l = valueLength;
          /** @type {number} */
          var X = 0;
          /** @type {number} */
          var valAcum = 0;
          for (;i < l;i++) {
            ctx.fillStyle = ctx.strokeStyle = colorArray[i % colorLength];
            if (gradient) {
              var linear;
              if (horz) {
                linear = ctx.createLinearGradient(x + dimArray[i] / 2, y + fixedDim * i, x + dimArray[i] / 2, y + fixedDim * (i + 1));
              } else {
                linear = ctx.createLinearGradient(x + fixedDim * i, y - dimArray[i] / 2, x + fixedDim * (i + 1), y - dimArray[i] / 2);
              }
              var color = $.rgbToHex($.map($.hexToRgb(colorArray[i % colorLength].slice(1)), function(dataAndEvents) {
                return dataAndEvents * 0.5 >> 0;
              }));
              linear.addColorStop(0, color);
              linear.addColorStop(0.5, colorArray[i % colorLength]);
              linear.addColorStop(1, color);
              ctx.fillStyle = linear;
            }
            if (horz) {
              ctx.fillRect(x, y + fixedDim * i, dimArray[i], fixedDim);
            } else {
              ctx.fillRect(x + fixedDim * i, y - dimArray[i], fixedDim, dimArray[i]);
            }
            if (border && border.name == stringArray[i]) {
              /** @type {number} */
              opt.acum = fixedDim * i;
              opt.dimValue = dimArray[i];
            }
            X += dimArray[i] || 0;
            valAcum += valueArray[i] || 0;
          }
          if (border) {
            ctx.save();
            /** @type {number} */
            ctx.lineWidth = 2;
            ctx.strokeStyle = border.color;
            if (horz) {
              ctx.strokeRect(x + 1, y + opt.acum + 1, opt.dimValue - 2, fixedDim - 2);
            } else {
              ctx.strokeRect(x + opt.acum + 1, y - opt.dimValue + 1, fixedDim - 2, opt.dimValue - 2);
            }
            ctx.restore();
          }
          if (label.type == "Native") {
            ctx.save();
            ctx.fillStyle = ctx.strokeStyle = label.color;
            /** @type {string} */
            ctx.font = label.style + " " + label.size + "px " + label.family;
            /** @type {string} */
            ctx.textBaseline = "middle";
            var aggValue = aggregates(node.name, valAcum, node);
            if (aggValue !== false) {
              aggValue = aggValue !== true ? aggValue : valAcum;
              if (horz) {
                /** @type {string} */
                ctx.textAlign = "right";
                ctx.fillText(aggValue, x + Math.max.apply(null, dimArray) - config.labelOffset, y + height / 2);
              } else {
                /** @type {string} */
                ctx.textAlign = "center";
                ctx.fillText(aggValue, x + width / 2, y - Math.max.apply(null, dimArray) - label.size / 2 - config.labelOffset);
              }
            }
            if (showLabels(node.name, valAcum, node)) {
              if (horz) {
                /** @type {string} */
                ctx.textAlign = "center";
                ctx.translate(x - config.labelOffset - label.size / 2, y + height / 2);
                ctx.rotate(Math.PI / 2);
                ctx.fillText(node.name, 0, 0);
              } else {
                /** @type {string} */
                ctx.textAlign = "center";
                ctx.fillText(node.name, x + width / 2, y + label.size / 2 + config.labelOffset);
              }
            }
            ctx.restore();
          }
        }
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {?}
       */
      contains : function(opt_attributes, value) {
        var pos = opt_attributes.pos.getc(true);
        var width = opt_attributes.getData("width");
        var height = opt_attributes.getData("height");
        var algnPos = this.getAlignedPos(pos, width, height);
        var x = algnPos.x;
        var y = algnPos.y;
        var codeSegments = opt_attributes.getData("dimArray");
        var valueLength = codeSegments.length;
        var config = opt_attributes.getData("config");
        /** @type {number} */
        var dx0 = value.x - x;
        /** @type {boolean} */
        var horz = config.orientation == "horizontal";
        /** @type {number} */
        var fixedDim = (horz ? height : width) / valueLength;
        if (horz) {
          if (value.x < x || (value.x > x + width || (value.y > y + height || value.y < y))) {
            return false;
          }
        } else {
          if (value.x < x || (value.x > x + width || (value.y > y || value.y < y - height))) {
            return false;
          }
        }
        /** @type {number} */
        var i = 0;
        var valuesLen = codeSegments.length;
        for (;i < valuesLen;i++) {
          var delta = codeSegments[i];
          if (horz) {
            var limit = y + fixedDim * i;
            if (value.x <= x + delta && (value.y >= limit && value.y <= limit + fixedDim)) {
              return{
                name : opt_attributes.getData("stringArray")[i],
                color : opt_attributes.getData("colorArray")[i],
                value : opt_attributes.getData("valueArray")[i],
                label : opt_attributes.name
              };
            }
          } else {
            limit = x + fixedDim * i;
            if (value.x >= limit && (value.x <= limit + fixedDim && value.y >= y - delta)) {
              return{
                name : opt_attributes.getData("stringArray")[i],
                color : opt_attributes.getData("colorArray")[i],
                value : opt_attributes.getData("valueArray")[i],
                label : opt_attributes.name
              };
            }
          }
        }
        return false;
      }
    }
  });
  $jit.BarChart = new Class({
    st : null,
    colors : ["#416D9C", "#70A35E", "#EBB056", "#C74243", "#83548B", "#909291", "#557EAA"],
    selected : {},
    busy : false,
    /**
     * @param {?} controller
     * @return {undefined}
     */
    initialize : function(controller) {
      this.controller = this.config = $.merge(Options("Canvas", "Margin", "Label", "BarChart"), {
        Label : {
          type : "Native"
        }
      }, controller);
      var showLabels = this.config.showLabels;
      var typeLabels = $.type(showLabels);
      var showAggregates = this.config.showAggregates;
      var typeAggregates = $.type(showAggregates);
      this.config.showLabels = typeLabels == "function" ? showLabels : $.lambda(showLabels);
      this.config.showAggregates = typeAggregates == "function" ? showAggregates : $.lambda(showAggregates);
      this.initializeViz();
    },
    /**
     * @return {undefined}
     */
    initializeViz : function() {
      var config = this.config;
      var that = this;
      var nodeType = config.type.split(":")[0];
      /** @type {boolean} */
      var horz = config.orientation == "horizontal";
      var nodeLabels = {};
      var delegate = new $jit.ST({
        injectInto : config.injectInto,
        width : config.width,
        height : config.height,
        orientation : horz ? "left" : "bottom",
        levelDistance : 0,
        siblingOffset : config.barsOffset,
        subtreeOffset : 0,
        withLabels : config.Label.type != "Native",
        useCanvas : config.useCanvas,
        Label : {
          type : config.Label.type
        },
        Node : {
          overridable : true,
          type : "barchart-" + nodeType,
          align : "left",
          width : 1,
          height : 1
        },
        Edge : {
          type : "none"
        },
        Tips : {
          enable : config.Tips.enable,
          type : "Native",
          force : true,
          /**
           * @param {?} from
           * @param {?} type
           * @param {?} event
           * @return {undefined}
           */
          onShow : function(from, type, event) {
            var lab = event;
            config.Tips.onShow(from, lab, type);
          }
        },
        Events : {
          enable : true,
          type : "Native",
          /**
           * @param {?} adj
           * @param {?} lab
           * @param {?} selector
           * @return {undefined}
           */
          onClick : function(adj, lab, selector) {
            if (!config.Events.enable) {
              return;
            }
            var from = lab.getContains();
            config.Events.onClick(from, lab, selector);
          },
          /**
           * @param {?} adj
           * @param {?} lab
           * @param {?} event
           * @return {undefined}
           */
          onMouseMove : function(adj, lab, event) {
            if (!config.hoveredColor) {
              return;
            }
            if (adj) {
              var elem = lab.getContains();
              that.select(adj.id, elem.name, elem.index);
            } else {
              that.select(false, false, false);
            }
          }
        },
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        onCreateLabel : function(adj, lab) {
          var labelConf = config.Label;
          var reversed = lab.getData("valueArray");
          var acumLeft = $.reduce(reversed, function(far, near) {
            return far + near;
          }, 0);
          var nlbs = {
            wrapper : document.createElement("div"),
            aggregate : document.createElement("div"),
            label : document.createElement("div")
          };
          /** @type {Element} */
          var wrapper = nlbs.wrapper;
          /** @type {Element} */
          var label = nlbs.label;
          /** @type {Element} */
          var aggregate = nlbs.aggregate;
          /** @type {(CSSStyleDeclaration|null)} */
          var wrapperStyle = wrapper.style;
          /** @type {(CSSStyleDeclaration|null)} */
          var labelStyle = label.style;
          /** @type {(CSSStyleDeclaration|null)} */
          var aggregateStyle = aggregate.style;
          nodeLabels[lab.id] = nlbs;
          wrapper.appendChild(label);
          wrapper.appendChild(aggregate);
          if (!config.showLabels(lab.name, acumLeft, lab)) {
            /** @type {string} */
            labelStyle.display = "none";
          }
          if (!config.showAggregates(lab.name, acumLeft, lab)) {
            /** @type {string} */
            aggregateStyle.display = "none";
          }
          /** @type {string} */
          wrapperStyle.position = "relative";
          /** @type {string} */
          wrapperStyle.overflow = "visible";
          /** @type {string} */
          wrapperStyle.fontSize = labelConf.size + "px";
          wrapperStyle.fontFamily = labelConf.family;
          wrapperStyle.color = labelConf.color;
          /** @type {string} */
          wrapperStyle.textAlign = "center";
          /** @type {string} */
          aggregateStyle.position = labelStyle.position = "absolute";
          adj.style.width = lab.getData("width") + "px";
          adj.style.height = lab.getData("height") + "px";
          /** @type {string} */
          aggregateStyle.left = labelStyle.left = "0px";
          label.innerHTML = lab.name;
          adj.appendChild(wrapper);
        },
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        onPlaceLabel : function(adj, lab) {
          if (!nodeLabels[lab.id]) {
            return;
          }
          var labels = nodeLabels[lab.id];
          var style = labels.wrapper.style;
          var labelStyle = labels.label.style;
          var aggregateStyle = labels.aggregate.style;
          /** @type {boolean} */
          var grouped = config.type.split(":")[0] == "grouped";
          /** @type {boolean} */
          var horz = config.orientation == "horizontal";
          var dimArray = lab.getData("dimArray");
          var valArray = lab.getData("valueArray");
          var w = grouped && horz ? Math.max.apply(null, dimArray) : lab.getData("width");
          var height = grouped && !horz ? Math.max.apply(null, dimArray) : lab.getData("height");
          /** @type {number} */
          var font = parseInt(style.fontSize, 10);
          var styleDeclaration = adj.style;
          if (dimArray && valArray) {
            /** @type {string} */
            style.width = aggregateStyle.width = labelStyle.width = adj.style.width = w + "px";
            /** @type {number} */
            var i = 0;
            var l = valArray.length;
            /** @type {number} */
            var acum = 0;
            for (;i < l;i++) {
              if (dimArray[i] > 0) {
                acum += valArray[i];
              }
            }
            if (config.showLabels(lab.name, acum, lab)) {
              /** @type {string} */
              labelStyle.display = "";
            } else {
              /** @type {string} */
              labelStyle.display = "none";
            }
            var aggValue = config.showAggregates(lab.name, acum, lab);
            if (aggValue !== false) {
              /** @type {string} */
              aggregateStyle.display = "";
            } else {
              /** @type {string} */
              aggregateStyle.display = "none";
            }
            if (config.orientation == "horizontal") {
              /** @type {string} */
              aggregateStyle.textAlign = "right";
              /** @type {string} */
              labelStyle.textAlign = "left";
              /** @type {string} */
              labelStyle.textIndex = aggregateStyle.textIndent = config.labelOffset + "px";
              /** @type {string} */
              aggregateStyle.top = labelStyle.top = (height - font) / 2 + "px";
              /** @type {string} */
              adj.style.height = style.height = height + "px";
            } else {
              /** @type {string} */
              aggregateStyle.top = -font - config.labelOffset + "px";
              /** @type {string} */
              labelStyle.top = config.labelOffset + height + "px";
              /** @type {string} */
              adj.style.top = parseInt(adj.style.top, 10) - height + "px";
              /** @type {string} */
              adj.style.height = style.height = height + "px";
            }
            labels.aggregate.innerHTML = aggValue !== true ? aggValue : acum;
          }
        }
      });
      var $cont = delegate.canvas.getSize();
      var margin = config.Margin;
      if (horz) {
        /** @type {number} */
        delegate.config.offsetX = $cont.width / 2 - margin.left - (config.showLabels && config.labelOffset + config.Label.size);
        /** @type {number} */
        delegate.config.offsetY = (margin.bottom - margin.top) / 2;
      } else {
        delegate.config.offsetY = -$cont.height / 2 + margin.bottom + (config.showLabels && config.labelOffset + config.Label.size);
        /** @type {number} */
        delegate.config.offsetX = (margin.right - margin.left) / 2;
      }
      this.delegate = delegate;
      this.canvas = this.delegate.canvas;
    },
    /**
     * @param {Object} json
     * @return {undefined}
     */
    loadJSON : function(json) {
      if (this.busy) {
        return;
      }
      /** @type {boolean} */
      this.busy = true;
      /** @type {number} */
      var prefix = $.time();
      /** @type {Array} */
      var ch = [];
      var delegate = this.delegate;
      var name = $.splat(json.label);
      var color = $.splat(json.color || this.colors);
      var config = this.config;
      /** @type {boolean} */
      var gradient = !!config.type.split(":")[1];
      var animate = config.animate;
      /** @type {boolean} */
      var isH = config.orientation == "horizontal";
      var that = this;
      /** @type {number} */
      var i = 0;
      var values = json.values;
      var valuesLen = values.length;
      for (;i < valuesLen;i++) {
        var value = values[i];
        var valArray = $.splat(values[i].values);
        /** @type {number} */
        var F = 0;
        ch.push({
          id : prefix + value.label,
          name : value.label,
          data : {
            value : valArray,
            "$valueArray" : valArray,
            "$colorArray" : color,
            "$stringArray" : name,
            "$gradient" : gradient,
            "$config" : config
          },
          children : []
        });
      }
      var root = {
        id : prefix + "$root",
        name : "",
        data : {
          "$type" : "none",
          "$width" : 1,
          "$height" : 1
        },
        children : ch
      };
      delegate.loadJSON(root);
      this.normalizeDims();
      delegate.compute();
      delegate.select(delegate.root);
      if (animate) {
        if (isH) {
          delegate.fx.animate({
            modes : ["node-property:width:dimArray"],
            duration : 1500,
            /**
             * @return {undefined}
             */
            onComplete : function() {
              /** @type {boolean} */
              that.busy = false;
            }
          });
        } else {
          delegate.fx.animate({
            modes : ["node-property:height:dimArray"],
            duration : 1500,
            /**
             * @return {undefined}
             */
            onComplete : function() {
              /** @type {boolean} */
              that.busy = false;
            }
          });
        }
      } else {
        /** @type {boolean} */
        this.busy = false;
      }
    },
    /**
     * @param {Object} json
     * @param {Object} onComplete
     * @return {undefined}
     */
    updateJSON : function(json, onComplete) {
      if (this.busy) {
        return;
      }
      /** @type {boolean} */
      this.busy = true;
      this.select(false, false, false);
      var delegate = this.delegate;
      var graph = delegate.graph;
      var attributes = json.values;
      var animate = this.config.animate;
      var that = this;
      /** @type {boolean} */
      var isH = this.config.orientation == "horizontal";
      $.each(attributes, function(v) {
        var n = graph.getByName(v.label);
        if (n) {
          n.setData("valueArray", $.splat(v.values));
          if (json.label) {
            n.setData("stringArray", $.splat(json.label));
          }
        }
      });
      this.normalizeDims();
      delegate.compute();
      delegate.select(delegate.root);
      if (animate) {
        if (isH) {
          delegate.fx.animate({
            modes : ["node-property:width:dimArray"],
            duration : 1500,
            /**
             * @return {undefined}
             */
            onComplete : function() {
              /** @type {boolean} */
              that.busy = false;
              if (onComplete) {
                onComplete.onComplete();
              }
            }
          });
        } else {
          delegate.fx.animate({
            modes : ["node-property:height:dimArray"],
            duration : 1500,
            /**
             * @return {undefined}
             */
            onComplete : function() {
              /** @type {boolean} */
              that.busy = false;
              if (onComplete) {
                onComplete.onComplete();
              }
            }
          });
        }
      }
    },
    /**
     * @param {string} id
     * @param {boolean} lab
     * @return {undefined}
     */
    select : function(id, lab) {
      if (!this.config.hoveredColor) {
        return;
      }
      var s = this.selected;
      if (s.id != id || s.name != lab) {
        /** @type {string} */
        s.id = id;
        /** @type {boolean} */
        s.name = lab;
        s.color = this.config.hoveredColor;
        this.delegate.graph.eachNode(function(n) {
          if (id == n.id) {
            n.setData("border", s);
          } else {
            n.setData("border", false);
          }
        });
        this.delegate.plot();
      }
    },
    /**
     * @return {?}
     */
    getLegend : function() {
      var legend = {};
      var n;
      this.delegate.graph.getNode(this.delegate.root).eachAdjacency(function(adj) {
        n = adj.nodeTo;
      });
      var colors = n.getData("colorArray");
      var colorsLen = colors.length;
      $.each(n.getData("stringArray"), function(s, i) {
        legend[s] = colors[i % colorsLen];
      });
      return legend;
    },
    /**
     * @return {?}
     */
    getMaxValue : function() {
      /** @type {number} */
      var maxValue = 0;
      /** @type {boolean} */
      var stacked = this.config.type.split(":")[0] == "stacked";
      this.delegate.graph.eachNode(function(n) {
        var attributes = n.getData("valueArray");
        /** @type {number} */
        var acum = 0;
        if (!attributes) {
          return;
        }
        if (stacked) {
          $.each(attributes, function(v) {
            acum += +v;
          });
        } else {
          /** @type {number} */
          acum = Math.max.apply(null, attributes);
        }
        maxValue = maxValue > acum ? maxValue : acum;
      });
      return maxValue;
    },
    /**
     * @param {string} type
     * @return {undefined}
     */
    setBarType : function(type) {
      /** @type {string} */
      this.config.type = type;
      this.delegate.config.Node.type = "barchart-" + type.split(":")[0];
    },
    /**
     * @return {undefined}
     */
    normalizeDims : function() {
      var root = this.delegate.graph.getNode(this.delegate.root);
      /** @type {number} */
      var l = 0;
      root.eachAdjacency(function() {
        l++;
      });
      var maxValue = this.getMaxValue() || 1;
      var size = this.delegate.canvas.getSize();
      var config = this.config;
      var margin = config.Margin;
      var marginWidth = margin.left + margin.right;
      var marginHeight = margin.top + margin.bottom;
      /** @type {boolean} */
      var horz = config.orientation == "horizontal";
      /** @type {number} */
      var fixedDim = (size[horz ? "height" : "width"] - (horz ? marginHeight : marginWidth) - (l - 1) * config.barsOffset) / l;
      var animate = config.animate;
      /** @type {number} */
      var height = size[horz ? "width" : "height"] - (horz ? marginWidth : marginHeight) - (!horz && (config.showAggregates && config.Label.size + config.labelOffset)) - (config.showLabels && config.Label.size + config.labelOffset);
      /** @type {string} */
      var dim1 = horz ? "height" : "width";
      /** @type {string} */
      var dim2 = horz ? "width" : "height";
      this.delegate.graph.eachNode(function(n) {
        /** @type {number} */
        var acum = 0;
        /** @type {Array} */
        var animateValue = [];
        $.each(n.getData("valueArray"), function(v) {
          acum += +v;
          animateValue.push(0);
        });
        n.setData(dim1, fixedDim);
        if (animate) {
          n.setData(dim2, acum * height / maxValue, "end");
          n.setData("dimArray", $.map(n.getData("valueArray"), function(n) {
            return n * height / maxValue;
          }), "end");
          var dimArray = n.getData("dimArray");
          if (!dimArray) {
            n.setData("dimArray", animateValue);
          }
        } else {
          n.setData(dim2, acum * height / maxValue);
          n.setData("dimArray", $.map(n.getData("valueArray"), function(n) {
            return n * height / maxValue;
          }));
        }
      });
    }
  });
  Options.PieChart = {
    $extend : true,
    animate : true,
    offset : 25,
    sliceOffset : 0,
    labelOffset : 3,
    type : "stacked",
    hoveredColor : "#9fd4ff",
    Events : {
      enable : false,
      /** @type {function (): undefined} */
      onClick : $.empty
    },
    Tips : {
      enable : false,
      /** @type {function (): undefined} */
      onShow : $.empty,
      /** @type {function (): undefined} */
      onHide : $.empty
    },
    showLabels : true,
    resizeLabels : false,
    updateHeights : false
  };
  Layout.Radial = new Class({
    /**
     * @param {?} adj
     * @return {undefined}
     */
    compute : function(adj) {
      var lab = $.splat(adj || ["current", "start", "end"]);
      column.compute(this.graph, lab, this.config);
      this.graph.computeLevels(this.root, 0, "ignore");
      var lengthFunc = this.createLevelDistanceFunc();
      this.computeAngularWidths(lab);
      this.computePositions(lab, lengthFunc);
    },
    /**
     * @param {?} node
     * @param {Object} getLength
     * @return {undefined}
     */
    computePositions : function(node, getLength) {
      var employees = node;
      var graph = this.graph;
      var root = graph.getNode(this.root);
      var parent = this.parent;
      var config = this.config;
      /** @type {number} */
      var i = 0;
      var l = employees.length;
      for (;i < l;i++) {
        var pi = employees[i];
        root.setPos($P(0, 0), pi);
        root.setData("span", Math.PI * 2, pi);
      }
      root.angleSpan = {
        begin : 0,
        end : 2 * Math.PI
      };
      graph.eachBFS(this.root, function(elem) {
        /** @type {number} */
        var angleSpan = elem.angleSpan.end - elem.angleSpan.begin;
        var angleInit = elem.angleSpan.begin;
        var len = getLength(elem);
        /** @type {number} */
        var totalAngularWidths = 0;
        /** @type {Array} */
        var subnodes = [];
        var maxDim = {};
        elem.eachSubnode(function(sib) {
          totalAngularWidths += sib._treeAngularWidth;
          /** @type {number} */
          var i = 0;
          var l = employees.length;
          for (;i < l;i++) {
            var pi = employees[i];
            var dim = sib.getData("dim", pi);
            maxDim[pi] = pi in maxDim ? dim > maxDim[pi] ? dim : maxDim[pi] : dim;
          }
          subnodes.push(sib);
        }, "ignore");
        if (parent && (parent.id == elem.id && (subnodes.length > 0 && subnodes[0].dist))) {
          subnodes.sort(function(a, b) {
            return(a.dist >= b.dist) - (a.dist <= b.dist);
          });
        }
        /** @type {number} */
        var i = 0;
        /** @type {number} */
        var valuesLen = subnodes.length;
        for (;i < valuesLen;i++) {
          var child = subnodes[i];
          if (!child._flag) {
            /** @type {number} */
            var angleProportion = child._treeAngularWidth / totalAngularWidths * angleSpan;
            var theta = angleInit + angleProportion / 2;
            /** @type {number} */
            var padIndex = 0;
            var l = employees.length;
            for (;padIndex < l;padIndex++) {
              var pi = employees[padIndex];
              child.setPos($P(theta, len), pi);
              child.setData("span", angleProportion, pi);
              child.setData("dim-quotient", child.getData("dim", pi) / maxDim[pi], pi);
            }
            child.angleSpan = {
              begin : angleInit,
              end : angleInit + angleProportion
            };
            angleInit += angleProportion;
          }
        }
      }, "ignore");
    },
    /**
     * @param {?} prop
     * @return {undefined}
     */
    setAngularWidthForNodes : function(prop) {
      this.graph.eachBFS(this.root, function(elem, i) {
        var diamValue = elem.getData("angularWidth", prop[0]) || 5;
        /** @type {number} */
        elem._angularWidth = diamValue / i;
      }, "ignore");
    },
    /**
     * @return {undefined}
     */
    setSubtreesAngularWidth : function() {
      var paragraph = this;
      this.graph.eachNode(function(child) {
        paragraph.setSubtreeAngularWidth(child);
      }, "ignore");
    },
    /**
     * @param {?} elem
     * @return {undefined}
     */
    setSubtreeAngularWidth : function(elem) {
      var paragraph = this;
      var nodeAW = elem._angularWidth;
      /** @type {number} */
      var sumAW = 0;
      elem.eachSubnode(function(child) {
        paragraph.setSubtreeAngularWidth(child);
        sumAW += child._treeAngularWidth;
      }, "ignore");
      /** @type {number} */
      elem._treeAngularWidth = Math.max(nodeAW, sumAW);
    },
    /**
     * @param {?} prop
     * @return {undefined}
     */
    computeAngularWidths : function(prop) {
      this.setAngularWidthForNodes(prop);
      this.setSubtreesAngularWidth();
    }
  });
  $jit.Sunburst = new Class({
    Implements : [valid, Extras, Layout.Radial],
    /**
     * @param {?} controller
     * @return {undefined}
     */
    initialize : function(controller) {
      var $Sunburst = $jit.Sunburst;
      var config = {
        interpolation : "linear",
        levelDistance : 100,
        Node : {
          type : "multipie",
          height : 0
        },
        Edge : {
          type : "none"
        },
        Label : {
          textAlign : "start",
          textBaseline : "middle"
        }
      };
      this.controller = this.config = $.merge(Options("Canvas", "Node", "Edge", "Fx", "Tips", "NodeStyles", "Events", "Navigation", "Controller", "Label"), config, controller);
      var canvasConfig = this.config;
      if (canvasConfig.useCanvas) {
        this.canvas = canvasConfig.useCanvas;
        /** @type {string} */
        this.config.labelContainer = this.canvas.id + "-label";
      } else {
        if (canvasConfig.background) {
          canvasConfig.background = $.merge({
            type : "Circles"
          }, canvasConfig.background);
        }
        this.canvas = new Canvas(this, canvasConfig);
        /** @type {string} */
        this.config.labelContainer = (typeof canvasConfig.injectInto == "string" ? canvasConfig.injectInto : canvasConfig.injectInto.id) + "-label";
      }
      this.graphOptions = {
        /** @type {function (number, number): undefined} */
        klass : Transform,
        Node : {
          selected : false,
          exist : true,
          drawn : true
        }
      };
      this.graph = new Graph(this.graphOptions, this.config.Node, this.config.Edge);
      this.labels = new $Sunburst.Label[canvasConfig.Label.type](this);
      this.fx = new $Sunburst.Plot(this, $Sunburst);
      this.op = new $Sunburst.Op(this);
      /** @type {null} */
      this.json = null;
      /** @type {null} */
      this.root = null;
      /** @type {null} */
      this.rotated = null;
      /** @type {boolean} */
      this.busy = false;
      this.initializeExtras();
    },
    /**
     * @return {?}
     */
    createLevelDistanceFunc : function() {
      var ld = this.config.levelDistance;
      return function(node) {
        return(node._depth + 1) * ld;
      };
    },
    /**
     * @return {undefined}
     */
    refresh : function() {
      this.compute();
      this.plot();
    },
    /**
     * @return {undefined}
     */
    reposition : function() {
      this.compute("end");
    },
    /**
     * @param {number} node
     * @param {string} method
     * @param {Object} opt
     * @return {undefined}
     */
    rotate : function(node, method, opt) {
      var theta = node.getPos(opt.property || "current").getp(true).theta;
      /** @type {number} */
      this.rotated = node;
      this.rotateAngle(-theta, method, opt);
    },
    /**
     * @param {number} theta
     * @param {string} method
     * @param {Object} opt
     * @return {undefined}
     */
    rotateAngle : function(theta, method, opt) {
      var z = this;
      var options = $.merge(this.config, opt || {}, {
        modes : ["polar"]
      });
      var prop = opt.property || (method === "animate" ? "end" : "current");
      if (method === "animate") {
        this.fx.animation.pause();
      }
      this.graph.eachNode(function(obj) {
        var p = obj.getPos(prop);
        p.theta += theta;
        if (p.theta < 0) {
          p.theta += Math.PI * 2;
        }
      });
      if (method == "animate") {
        this.fx.animate(options);
      } else {
        if (method == "replot") {
          this.fx.plot();
          /** @type {boolean} */
          this.busy = false;
        }
      }
    },
    /**
     * @return {undefined}
     */
    plot : function() {
      this.fx.plot();
    }
  });
  /** @type {boolean} */
  $jit.Sunburst.$extend = true;
  (function(Hypertree) {
    Hypertree.Op = new Class({
      Implements : Graph.Op
    });
    Hypertree.Plot = new Class({
      Implements : Graph.Plot
    });
    Hypertree.Label = {};
    Hypertree.Label.Native = new Class({
      Implements : Graph.Label.Native,
      /**
       * @param {?} viz
       * @return {undefined}
       */
      initialize : function(viz) {
        this.viz = viz;
        this.label = viz.config.Label;
        this.config = viz.config;
      },
      /**
       * @param {?} canvas
       * @param {Object} node
       * @param {?} controller
       * @return {undefined}
       */
      renderLabel : function(canvas, node, controller) {
        var span = node.getData("span");
        if (span < Math.PI / 2 && Math.tan(span) * this.config.levelDistance * node._depth < 10) {
          return;
        }
        var ctx = canvas.getCtx();
        var innerSize = ctx.measureText(node.name);
        if (node.id == this.viz.root) {
          /** @type {number} */
          var x = -innerSize.width / 2;
          /** @type {number} */
          var y = 0;
          /** @type {number} */
          var thetap = 0;
          /** @type {number} */
          var ld = 0;
        } else {
          /** @type {number} */
          var indent = 5;
          /** @type {number} */
          ld = controller.levelDistance - indent;
          var clone = node.pos.clone();
          clone.rho += indent;
          var p = clone.getp(true);
          var scroll = clone.getc(true);
          x = scroll.x;
          y = scroll.y;
          /** @type {number} */
          var pi = Math.PI;
          /** @type {boolean} */
          var cond = p.theta > pi / 2 && p.theta < 3 * pi / 2;
          thetap = cond ? p.theta + pi : p.theta;
          if (cond) {
            x -= Math.abs(Math.cos(p.theta) * innerSize.width);
            y += Math.sin(p.theta) * innerSize.width;
          } else {
            if (node.id == this.viz.root) {
              x -= innerSize.width / 2;
            }
          }
        }
        ctx.save();
        ctx.translate(x, y);
        ctx.rotate(thetap);
        ctx.fillText(node.name, 0, 0);
        ctx.restore();
      }
    });
    Hypertree.Label.SVG = new Class({
      Implements : Graph.Label.SVG,
      /**
       * @param {?} viz
       * @return {undefined}
       */
      initialize : function(viz) {
        this.viz = viz;
      },
      /**
       * @param {?} from
       * @param {?} lab
       * @param {?} options
       * @return {undefined}
       */
      placeLabel : function(from, lab, options) {
        var offsetCoordinate = lab.pos.getc(true);
        var viz = this.viz;
        var canvas = this.viz.canvas;
        var $cont = canvas.getSize();
        var tl = {
          x : Math.round(offsetCoordinate.x + $cont.width / 2),
          y : Math.round(offsetCoordinate.y + $cont.height / 2)
        };
        from.setAttribute("x", tl.x);
        from.setAttribute("y", tl.y);
        var bb = from.getBBox();
        if (bb) {
          var x = from.getAttribute("x");
          var y = from.getAttribute("y");
          var p = lab.pos.getp(true);
          /** @type {number} */
          var pi = Math.PI;
          /** @type {boolean} */
          var cond = p.theta > pi / 2 && p.theta < 3 * pi / 2;
          if (cond) {
            from.setAttribute("x", x - bb.width);
            from.setAttribute("y", y - bb.height);
          } else {
            if (lab.id == viz.root) {
              from.setAttribute("x", x - bb.width / 2);
            }
          }
          var thetap = cond ? p.theta + pi : p.theta;
          if (lab._depth) {
            from.setAttribute("transform", "rotate(" + thetap * 360 / (2 * pi) + " " + x + " " + y + ")");
          }
        }
        options.onPlaceLabel(from, lab);
      }
    });
    Hypertree.Label.HTML = new Class({
      Implements : Graph.Label.HTML,
      /**
       * @param {?} viz
       * @return {undefined}
       */
      initialize : function(viz) {
        this.viz = viz;
      },
      /**
       * @param {?} from
       * @param {?} lab
       * @param {?} options
       * @return {undefined}
       */
      placeLabel : function(from, lab, options) {
        var pos = lab.pos.clone();
        var canvas = this.viz.canvas;
        var height = lab.getData("height");
        /** @type {number} */
        var ldist = (height || lab._depth == 0 ? height : this.viz.config.levelDistance) / 2;
        var $cont = canvas.getSize();
        pos.rho += ldist;
        pos = pos.getc(true);
        var labelPos = {
          x : Math.round(pos.x + $cont.width / 2),
          y : Math.round(pos.y + $cont.height / 2)
        };
        var style = from.style;
        /** @type {string} */
        style.left = labelPos.x + "px";
        /** @type {string} */
        style.top = labelPos.y + "px";
        /** @type {string} */
        style.display = this.fitsInCanvas(labelPos, canvas) ? "" : "none";
        options.onPlaceLabel(from, lab);
      }
    });
    Hypertree.Plot.NodeTypes = new Class({
      none : {
        /** @type {function (): undefined} */
        render : $.empty,
        contains : $.lambda(false),
        /**
         * @param {Object} node
         * @param {?} pos
         * @return {?}
         */
        anglecontains : function(node, pos) {
          /** @type {number} */
          var span = node.getData("span") / 2;
          var theta = node.pos.theta;
          /** @type {number} */
          var begin = theta - span;
          var end = theta + span;
          if (begin < 0) {
            begin += Math.PI * 2;
          }
          /** @type {number} */
          var atan = Math.atan2(pos.y, pos.x);
          if (atan < 0) {
            atan += Math.PI * 2;
          }
          if (begin > end) {
            return atan > begin && atan <= Math.PI * 2 || atan < end;
          } else {
            return atan > begin && atan < end;
          }
        }
      },
      pie : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          /** @type {number} */
          var span = adj.getData("span") / 2;
          var theta = adj.pos.theta;
          /** @type {number} */
          var begin = theta - span;
          var end = theta + span;
          var polarNode = adj.pos.getp(true);
          var polar = new Transform(polarNode.rho, begin);
          var p4coord = polar.getc(true);
          polar.theta = end;
          var endPoint = polar.getc(true);
          var ctx = lab.getCtx();
          ctx.beginPath();
          ctx.moveTo(0, 0);
          ctx.lineTo(p4coord.x, p4coord.y);
          ctx.moveTo(0, 0);
          ctx.lineTo(endPoint.x, endPoint.y);
          ctx.moveTo(0, 0);
          ctx.arc(0, 0, polarNode.rho * adj.getData("dim-quotient"), begin, end, false);
          ctx.fill();
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          if (this.nodeTypes.none.anglecontains.call(this, opt_attributes, value)) {
            /** @type {number} */
            var rho = Math.sqrt(value.x * value.x + value.y * value.y);
            var ld = this.config.levelDistance;
            var d = opt_attributes._depth;
            return rho <= ld * d;
          }
          return false;
        }
      },
      multipie : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var height = adj.getData("height");
          var ldist = height ? height : this.config.levelDistance;
          /** @type {number} */
          var span = adj.getData("span") / 2;
          var theta = adj.pos.theta;
          /** @type {number} */
          var begin = theta - span;
          var end = theta + span;
          var polarNode = adj.pos.getp(true);
          var polar = new Transform(polarNode.rho, begin);
          var s1 = polar.getc(true);
          polar.theta = end;
          var pt1 = polar.getc(true);
          polar.rho += ldist;
          var p4coord = polar.getc(true);
          /** @type {number} */
          polar.theta = begin;
          var endPoint = polar.getc(true);
          var ctx = lab.getCtx();
          ctx.moveTo(0, 0);
          ctx.beginPath();
          ctx.arc(0, 0, polarNode.rho, begin, end, false);
          ctx.arc(0, 0, polarNode.rho + ldist, end, begin, true);
          ctx.moveTo(s1.x, s1.y);
          ctx.lineTo(endPoint.x, endPoint.y);
          ctx.moveTo(pt1.x, pt1.y);
          ctx.lineTo(p4coord.x, p4coord.y);
          ctx.fill();
          if (adj.collapsed) {
            ctx.save();
            /** @type {number} */
            ctx.lineWidth = 2;
            ctx.moveTo(0, 0);
            ctx.beginPath();
            ctx.arc(0, 0, polarNode.rho + ldist + 5, end - 0.01, begin + 0.01, true);
            ctx.stroke();
            ctx.restore();
          }
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          if (this.nodeTypes.none.anglecontains.call(this, opt_attributes, value)) {
            /** @type {number} */
            var rho = Math.sqrt(value.x * value.x + value.y * value.y);
            var height = opt_attributes.getData("height");
            var ldist = height ? height : this.config.levelDistance;
            var ld = this.config.levelDistance;
            var d = opt_attributes._depth;
            return rho >= ld * d && rho <= ld * d + ldist;
          }
          return false;
        }
      },
      "gradient-multipie" : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var ctx = lab.getCtx();
          var height = adj.getData("height");
          var ldist = height ? height : this.config.levelDistance;
          var radialGradient = ctx.createRadialGradient(0, 0, adj.getPos().rho, 0, 0, adj.getPos().rho + ldist);
          var attributes = $.hexToRgb(adj.getData("color"));
          /** @type {Array} */
          var ans = [];
          $.each(attributes, function(i) {
            ans.push(parseInt(i * 0.5, 10));
          });
          var endColor = $.rgbToHex(ans);
          radialGradient.addColorStop(0, endColor);
          radialGradient.addColorStop(1, adj.getData("color"));
          ctx.fillStyle = radialGradient;
          this.nodeTypes.multipie.render.call(this, adj, lab);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          return this.nodeTypes.multipie.contains.call(this, opt_attributes, value);
        }
      },
      "gradient-pie" : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var ctx = lab.getCtx();
          var radialGradient = ctx.createRadialGradient(0, 0, 0, 0, 0, adj.getPos().rho);
          var attributes = $.hexToRgb(adj.getData("color"));
          /** @type {Array} */
          var ans = [];
          $.each(attributes, function(i) {
            ans.push(parseInt(i * 0.5, 10));
          });
          var endColor = $.rgbToHex(ans);
          radialGradient.addColorStop(1, endColor);
          radialGradient.addColorStop(0, adj.getData("color"));
          ctx.fillStyle = radialGradient;
          this.nodeTypes.pie.render.call(this, adj, lab);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          return this.nodeTypes.pie.contains.call(this, opt_attributes, value);
        }
      }
    });
    Hypertree.Plot.EdgeTypes = new Class({
      /** @type {function (): undefined} */
      none : $.empty,
      line : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var from = adj.nodeFrom.pos.getc(true);
          var lab = adj.nodeTo.pos.getc(true);
          this.edgeHelper.line.render(from, lab, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.nodeFrom.pos.getc(true);
          var pdataOld = opt_attributes.nodeTo.pos.getc(true);
          return this.edgeHelper.line.contains(attributes, pdataOld, value, this.edge.epsilon);
        }
      },
      arrow : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var from = adj.nodeFrom.pos.getc(true);
          var lab = adj.nodeTo.pos.getc(true);
          var qualifier = adj.getData("dim");
          var direction = adj.data.$direction;
          var cycle = direction && (direction.length > 1 && direction[0] != adj.nodeFrom.id);
          this.edgeHelper.arrow.render(from, lab, qualifier, cycle, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.nodeFrom.pos.getc(true);
          var pdataOld = opt_attributes.nodeTo.pos.getc(true);
          return this.edgeHelper.arrow.contains(attributes, pdataOld, value, this.edge.epsilon);
        }
      },
      hyperline : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var p = adj.nodeFrom.pos.getc();
          var Vec3 = adj.nodeTo.pos.getc();
          /** @type {number} */
          var qualifier = Math.max(p.norm(), Vec3.norm());
          this.edgeHelper.hyperline.render(p.$scale(1 / qualifier), Vec3.$scale(1 / qualifier), qualifier, lab);
        },
        contains : $.lambda(false)
      }
    });
  })($jit.Sunburst);
  $jit.Sunburst.Plot.NodeTypes.implement({
    "piechart-stacked" : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @return {undefined}
       */
      render : function(adj, lab) {
        var T = adj.pos.getp(true);
        var dimArray = adj.getData("dimArray");
        var valueArray = adj.getData("valueArray");
        var colorArray = adj.getData("colorArray");
        var colorLength = colorArray.length;
        var stringArray = adj.getData("stringArray");
        /** @type {number} */
        var span = adj.getData("span") / 2;
        var theta = adj.pos.theta;
        /** @type {number} */
        var begin = theta - span;
        var end = theta + span;
        var polar = new Transform;
        var ctx = lab.getCtx();
        var opt = {};
        var gradient = adj.getData("gradient");
        var border = adj.getData("border");
        var config = adj.getData("config");
        var showLabels = config.showLabels;
        var resizeLabels = config.resizeLabels;
        var label = config.Label;
        /** @type {number} */
        var cx = config.sliceOffset * Math.cos((begin + end) / 2);
        /** @type {number} */
        var cy = config.sliceOffset * Math.sin((begin + end) / 2);
        if (colorArray && (dimArray && stringArray)) {
          /** @type {number} */
          var i = 0;
          var l = dimArray.length;
          /** @type {number} */
          var acum = 0;
          /** @type {number} */
          var X = 0;
          for (;i < l;i++) {
            var dimi = dimArray[i];
            var color = colorArray[i % colorLength];
            if (dimi <= 0) {
              continue;
            }
            ctx.fillStyle = ctx.strokeStyle = color;
            if (gradient && dimi) {
              var grad = ctx.createRadialGradient(cx, cy, acum + config.sliceOffset, cx, cy, acum + dimi + config.sliceOffset);
              var a = $.hexToRgb(color);
              var ans = $.map(a, function(dataAndEvents) {
                return dataAndEvents * 0.8 >> 0;
              });
              var endColor = $.rgbToHex(ans);
              grad.addColorStop(0, color);
              grad.addColorStop(0.5, color);
              grad.addColorStop(1, endColor);
              ctx.fillStyle = grad;
            }
            polar.rho = acum + config.sliceOffset;
            /** @type {number} */
            polar.theta = begin;
            var ah = polar.getc(true);
            polar.theta = end;
            var O = polar.getc(true);
            polar.rho += dimi;
            var aj = polar.getc(true);
            /** @type {number} */
            polar.theta = begin;
            var Q = polar.getc(true);
            ctx.beginPath();
            ctx.arc(cx, cy, acum + 0.01, begin, end, false);
            ctx.arc(cx, cy, acum + dimi + 0.01, end, begin, true);
            ctx.fill();
            if (border && border.name == stringArray[i]) {
              opt.acum = acum;
              opt.dimValue = dimArray[i];
              /** @type {number} */
              opt.begin = begin;
              opt.end = end;
            }
            acum += dimi || 0;
            X += valueArray[i] || 0;
          }
          if (border) {
            ctx.save();
            /** @type {string} */
            ctx.globalCompositeOperation = "source-over";
            /** @type {number} */
            ctx.lineWidth = 2;
            ctx.strokeStyle = border.color;
            /** @type {number} */
            var aa = begin < end ? 1 : -1;
            ctx.beginPath();
            ctx.arc(cx, cy, opt.acum + 0.01 + 1, opt.begin, opt.end, false);
            ctx.arc(cx, cy, opt.acum + opt.dimValue + 0.01 - 1, opt.end, opt.begin, true);
            ctx.closePath();
            ctx.stroke();
            ctx.restore();
          }
          if (showLabels && label.type == "Native") {
            ctx.save();
            ctx.fillStyle = ctx.strokeStyle = label.color;
            var scale = resizeLabels ? adj.getData("normalizedDim") : 1;
            /** @type {number} */
            var fontSize = label.size * scale >> 0;
            /** @type {number} */
            fontSize = fontSize < +resizeLabels ? +resizeLabels : fontSize;
            /** @type {string} */
            ctx.font = label.style + " " + fontSize + "px " + label.family;
            /** @type {string} */
            ctx.textBaseline = "middle";
            /** @type {string} */
            ctx.textAlign = "center";
            polar.rho = acum + config.labelOffset + config.sliceOffset;
            polar.theta = adj.pos.theta;
            var cart = polar.getc(true);
            ctx.fillText(adj.name, cart.x, cart.y);
            ctx.restore();
          }
        }
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {?}
       */
      contains : function(opt_attributes, value) {
        if (this.nodeTypes.none.anglecontains.call(this, opt_attributes, value)) {
          /** @type {number} */
          var rho = Math.sqrt(value.x * value.x + value.y * value.y);
          var ld = this.config.levelDistance;
          var d = opt_attributes._depth;
          var config = opt_attributes.getData("config");
          if (rho <= ld * d + config.sliceOffset) {
            var dimArray = opt_attributes.getData("dimArray");
            /** @type {number} */
            var i = 0;
            var l = dimArray.length;
            var acum = config.sliceOffset;
            for (;i < l;i++) {
              var dimi = dimArray[i];
              if (rho >= acum && rho <= acum + dimi) {
                return{
                  name : opt_attributes.getData("stringArray")[i],
                  color : opt_attributes.getData("colorArray")[i],
                  value : opt_attributes.getData("valueArray")[i],
                  label : opt_attributes.name
                };
              }
              acum += dimi;
            }
          }
          return false;
        }
        return false;
      }
    }
  });
  $jit.PieChart = new Class({
    sb : null,
    colors : ["#416D9C", "#70A35E", "#EBB056", "#C74243", "#83548B", "#909291", "#557EAA"],
    selected : {},
    busy : false,
    /**
     * @param {?} controller
     * @return {undefined}
     */
    initialize : function(controller) {
      this.controller = this.config = $.merge(Options("Canvas", "PieChart", "Label"), {
        Label : {
          type : "Native"
        }
      }, controller);
      this.initializeViz();
    },
    /**
     * @return {undefined}
     */
    initializeViz : function() {
      var config = this.config;
      var that = this;
      var nodeType = config.type.split(":")[0];
      var delegate = new $jit.Sunburst({
        injectInto : config.injectInto,
        width : config.width,
        height : config.height,
        useCanvas : config.useCanvas,
        withLabels : config.Label.type != "Native",
        Label : {
          type : config.Label.type
        },
        Node : {
          overridable : true,
          type : "piechart-" + nodeType,
          width : 1,
          height : 1
        },
        Edge : {
          type : "none"
        },
        Tips : {
          enable : config.Tips.enable,
          type : "Native",
          force : true,
          /**
           * @param {?} from
           * @param {?} type
           * @param {?} event
           * @return {undefined}
           */
          onShow : function(from, type, event) {
            var lab = event;
            config.Tips.onShow(from, lab, type);
          }
        },
        Events : {
          enable : true,
          type : "Native",
          /**
           * @param {?} adj
           * @param {?} lab
           * @param {?} selector
           * @return {undefined}
           */
          onClick : function(adj, lab, selector) {
            if (!config.Events.enable) {
              return;
            }
            var from = lab.getContains();
            config.Events.onClick(from, lab, selector);
          },
          /**
           * @param {?} adj
           * @param {?} lab
           * @param {?} event
           * @return {undefined}
           */
          onMouseMove : function(adj, lab, event) {
            if (!config.hoveredColor) {
              return;
            }
            if (adj) {
              var elem = lab.getContains();
              that.select(adj.id, elem.name, elem.index);
            } else {
              that.select(false, false, false);
            }
          }
        },
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        onCreateLabel : function(adj, lab) {
          var labelConf = config.Label;
          if (config.showLabels) {
            var wrapperStyle = adj.style;
            /** @type {string} */
            wrapperStyle.fontSize = labelConf.size + "px";
            wrapperStyle.fontFamily = labelConf.family;
            wrapperStyle.color = labelConf.color;
            /** @type {string} */
            wrapperStyle.textAlign = "center";
            adj.innerHTML = lab.name;
          }
        },
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        onPlaceLabel : function(adj, lab) {
          if (!config.showLabels) {
            return;
          }
          var offsetCoordinate = lab.pos.getp(true);
          var dimArray = lab.getData("dimArray");
          /** @type {number} */
          var span = lab.getData("span") / 2;
          var theta = lab.pos.theta;
          /** @type {number} */
          var begin = theta - span;
          var end = theta + span;
          var polar = new Transform;
          var showLabels = config.showLabels;
          var resizeLabels = config.resizeLabels;
          var label = config.Label;
          if (dimArray) {
            /** @type {number} */
            var i = 0;
            var l = dimArray.length;
            /** @type {number} */
            var acum = 0;
            for (;i < l;i++) {
              acum += dimArray[i];
            }
            var scale = resizeLabels ? lab.getData("normalizedDim") : 1;
            /** @type {number} */
            var fontSize = label.size * scale >> 0;
            /** @type {number} */
            fontSize = fontSize < +resizeLabels ? +resizeLabels : fontSize;
            /** @type {string} */
            adj.style.fontSize = fontSize + "px";
            polar.rho = acum + config.labelOffset + config.sliceOffset;
            /** @type {number} */
            polar.theta = (begin + end) / 2;
            offsetCoordinate = polar.getc(true);
            var $cont = that.canvas.getSize();
            var pos = {
              x : Math.round(offsetCoordinate.x + $cont.width / 2),
              y : Math.round(offsetCoordinate.y + $cont.height / 2)
            };
            /** @type {string} */
            adj.style.left = pos.x + "px";
            /** @type {string} */
            adj.style.top = pos.y + "px";
          }
        }
      });
      var size = delegate.canvas.getSize();
      /** @type {function (...[*]): number} */
      var min = Math.min;
      /** @type {number} */
      delegate.config.levelDistance = min(size.width, size.height) / 2 - config.offset - config.sliceOffset;
      this.delegate = delegate;
      this.canvas = this.delegate.canvas;
      /** @type {string} */
      this.canvas.getCtx().globalCompositeOperation = "lighter";
    },
    /**
     * @param {Object} json
     * @return {undefined}
     */
    loadJSON : function(json) {
      /** @type {number} */
      var prefix = $.time();
      /** @type {Array} */
      var ch = [];
      var delegate = this.delegate;
      var resolveValues = $.splat(json.label);
      var length = resolveValues.length;
      var color = $.splat(json.color || this.colors);
      var colorLength = color.length;
      var config = this.config;
      /** @type {boolean} */
      var gradient = !!config.type.split(":")[1];
      var animate = config.animate;
      /** @type {boolean} */
      var mono = length == 1;
      /** @type {number} */
      var i = 0;
      var values = json.values;
      var valuesLen = values.length;
      for (;i < valuesLen;i++) {
        var val = values[i];
        var valArray = $.splat(val.values);
        ch.push({
          id : prefix + val.label,
          name : val.label,
          data : {
            value : valArray,
            "$valueArray" : valArray,
            "$colorArray" : mono ? $.splat(color[i % colorLength]) : color,
            "$stringArray" : resolveValues,
            "$gradient" : gradient,
            "$config" : config,
            "$angularWidth" : $.reduce(valArray, function(far, near) {
              return far + near;
            })
          },
          children : []
        });
      }
      var root = {
        id : prefix + "$root",
        name : "",
        data : {
          "$type" : "none",
          "$width" : 1,
          "$height" : 1
        },
        children : ch
      };
      delegate.loadJSON(root);
      this.normalizeDims();
      delegate.refresh();
      if (animate) {
        delegate.fx.animate({
          modes : ["node-property:dimArray"],
          duration : 1500
        });
      }
    },
    /**
     * @param {Object} json
     * @param {Object} onComplete
     * @return {undefined}
     */
    updateJSON : function(json, onComplete) {
      if (this.busy) {
        return;
      }
      /** @type {boolean} */
      this.busy = true;
      var delegate = this.delegate;
      var graph = delegate.graph;
      var attributes = json.values;
      var animate = this.config.animate;
      var that = this;
      $.each(attributes, function(v) {
        var n = graph.getByName(v.label);
        var vals = $.splat(v.values);
        if (n) {
          n.setData("valueArray", vals);
          n.setData("angularWidth", $.reduce(vals, function(far, near) {
            return far + near;
          }));
          if (json.label) {
            n.setData("stringArray", $.splat(json.label));
          }
        }
      });
      this.normalizeDims();
      if (animate) {
        delegate.compute("end");
        delegate.fx.animate({
          modes : ["node-property:dimArray:span", "linear"],
          duration : 1500,
          /**
           * @return {undefined}
           */
          onComplete : function() {
            /** @type {boolean} */
            that.busy = false;
            if (onComplete) {
              onComplete.onComplete();
            }
          }
        });
      } else {
        delegate.refresh();
      }
    },
    /**
     * @param {?} id
     * @param {boolean} lab
     * @return {undefined}
     */
    select : function(id, lab) {
      if (!this.config.hoveredColor) {
        return;
      }
      var s = this.selected;
      if (s.id != id || s.name != lab) {
        s.id = id;
        /** @type {boolean} */
        s.name = lab;
        s.color = this.config.hoveredColor;
        this.delegate.graph.eachNode(function(n) {
          if (id == n.id) {
            n.setData("border", s);
          } else {
            n.setData("border", false);
          }
        });
        this.delegate.plot();
      }
    },
    /**
     * @return {?}
     */
    getLegend : function() {
      var legend = {};
      var n;
      this.delegate.graph.getNode(this.delegate.root).eachAdjacency(function(adj) {
        n = adj.nodeTo;
      });
      var colors = n.getData("colorArray");
      var colorsLen = colors.length;
      $.each(n.getData("stringArray"), function(s, i) {
        legend[s] = colors[i % colorsLen];
      });
      return legend;
    },
    /**
     * @return {?}
     */
    getMaxValue : function() {
      /** @type {number} */
      var maxValue = 0;
      this.delegate.graph.eachNode(function(n) {
        var attributes = n.getData("valueArray");
        /** @type {number} */
        var acum = 0;
        $.each(attributes, function(v) {
          acum += +v;
        });
        maxValue = maxValue > acum ? maxValue : acum;
      });
      return maxValue;
    },
    /**
     * @return {undefined}
     */
    normalizeDims : function() {
      var root = this.delegate.graph.getNode(this.delegate.root);
      /** @type {number} */
      var w = 0;
      root.eachAdjacency(function() {
        w++;
      });
      var maxValue = this.getMaxValue() || 1;
      var config = this.config;
      var animate = config.animate;
      var rho = this.delegate.config.levelDistance;
      this.delegate.graph.eachNode(function(n) {
        /** @type {number} */
        var acum = 0;
        /** @type {Array} */
        var animateValue = [];
        $.each(n.getData("valueArray"), function(v) {
          acum += +v;
          animateValue.push(1);
        });
        /** @type {boolean} */
        var stat = animateValue.length == 1 && !config.updateHeights;
        if (animate) {
          n.setData("dimArray", $.map(n.getData("valueArray"), function(n) {
            return stat ? rho : n * rho / maxValue;
          }), "end");
          var dimArray = n.getData("dimArray");
          if (!dimArray) {
            n.setData("dimArray", animateValue);
          }
        } else {
          n.setData("dimArray", $.map(n.getData("valueArray"), function(n) {
            return stat ? rho : n * rho / maxValue;
          }));
        }
        n.setData("normalizedDim", acum / maxValue);
      });
    }
  });
  Layout.TM = {};
  Layout.TM.SliceAndDice = new Class({
    /**
     * @param {?} adj
     * @return {undefined}
     */
    compute : function(adj) {
      var from = this.graph.getNode(this.clickedNode && this.clickedNode.id || this.root);
      this.controller.onBeforeCompute(from);
      var size = this.canvas.getSize();
      var config = this.config;
      var width = size.width;
      var height = size.height;
      this.graph.computeLevels(this.root, 0, "ignore");
      from.getPos(adj).setc(-width / 2, -height / 2);
      from.setData("width", width, adj);
      from.setData("height", height + config.titleHeight, adj);
      this.computePositions(from, from, this.layout.orientation, adj);
      this.controller.onAfterCompute(from);
    },
    /**
     * @param {?} node
     * @param {Object} ch
     * @param {string} orn
     * @param {Object} prop
     * @return {undefined}
     */
    computePositions : function(node, ch, orn, prop) {
      /** @type {number} */
      var totalArea = 0;
      node.eachSubnode(function(n) {
        totalArea += n.getData("area", prop);
      });
      var config = this.config;
      var offset = config.offset;
      var val = node.getData("width", prop);
      /** @type {number} */
      var value = Math.max(node.getData("height", prop) - config.titleHeight, 0);
      /** @type {number} */
      var pow = node == ch ? 1 : ch.getData("area", prop) / totalArea;
      var result;
      var size;
      var dim;
      var pos;
      var pos2;
      var posth;
      var pos2th;
      /** @type {boolean} */
      var horizontal = orn == "h";
      if (horizontal) {
        /** @type {string} */
        orn = "v";
        /** @type {number} */
        result = value;
        /** @type {number} */
        size = val * pow;
        /** @type {string} */
        dim = "height";
        /** @type {string} */
        pos = "y";
        /** @type {string} */
        pos2 = "x";
        posth = config.titleHeight;
        /** @type {number} */
        pos2th = 0;
      } else {
        /** @type {string} */
        orn = "h";
        /** @type {number} */
        result = value * pow;
        size = val;
        /** @type {string} */
        dim = "width";
        /** @type {string} */
        pos = "x";
        /** @type {string} */
        pos2 = "y";
        /** @type {number} */
        posth = 0;
        pos2th = config.titleHeight;
      }
      var cpos = ch.getPos(prop);
      ch.setData("width", size, prop);
      ch.setData("height", result, prop);
      /** @type {number} */
      var offsetSize = 0;
      var tm = this;
      ch.eachSubnode(function(n) {
        var p = n.getPos(prop);
        p[pos] = offsetSize + cpos[pos] + posth;
        p[pos2] = cpos[pos2] + pos2th;
        tm.computePositions(ch, n, orn, prop);
        offsetSize += n.getData(dim, prop);
      });
    }
  });
  Layout.TM.Area = {
    /**
     * @param {string} adj
     * @return {undefined}
     */
    compute : function(adj) {
      adj = adj || "current";
      var from = this.graph.getNode(this.clickedNode && this.clickedNode.id || this.root);
      this.controller.onBeforeCompute(from);
      var config = this.config;
      var cs = this.canvas.getSize();
      var len = cs.width;
      var h = cs.height;
      var start = config.offset;
      /** @type {number} */
      var size = len - start;
      /** @type {number} */
      var offhght = h - start;
      this.graph.computeLevels(this.root, 0, "ignore");
      from.getPos(adj).setc(-len / 2, -h / 2);
      from.setData("width", len, adj);
      from.setData("height", h, adj);
      var coord = {
        top : -h / 2 + config.titleHeight,
        left : -len / 2,
        width : size,
        height : offhght - config.titleHeight
      };
      this.computePositions(from, coord, adj);
      this.controller.onAfterCompute(from);
    },
    /**
     * @param {string} tail
     * @param {?} initElem
     * @param {number} w
     * @param {?} coord
     * @param {?} comp
     * @param {Object} prop
     * @return {undefined}
     */
    computeDim : function(tail, initElem, w, coord, comp, prop) {
      if (tail.length + initElem.length == 1) {
        var l = tail.length == 1 ? tail : initElem;
        this.layoutLast(l, w, coord, prop);
        return;
      }
      if (tail.length >= 2 && initElem.length == 0) {
        /** @type {Array} */
        initElem = [tail.shift()];
      }
      if (tail.length == 0) {
        if (initElem.length > 0) {
          this.layoutRow(initElem, w, coord, prop);
        }
        return;
      }
      var c = tail[0];
      if (comp(initElem, w) >= comp([c].concat(initElem), w)) {
        this.computeDim(tail.slice(1), initElem.concat([c]), w, coord, comp, prop);
      } else {
        var newCoords = this.layoutRow(initElem, w, coord, prop);
        this.computeDim(tail, [], newCoords.dim, newCoords, comp, prop);
      }
    },
    /**
     * @param {Array} ch
     * @param {number} w
     * @return {?}
     */
    worstAspectRatio : function(ch, w) {
      if (!ch || ch.length == 0) {
        return Number.MAX_VALUE;
      }
      /** @type {number} */
      var areaSum = 0;
      /** @type {number} */
      var maxArea = 0;
      /** @type {number} */
      var minArea = Number.MAX_VALUE;
      /** @type {number} */
      var i = 0;
      var l = ch.length;
      for (;i < l;i++) {
        var area = ch[i]._area;
        areaSum += area;
        minArea = minArea < area ? minArea : area;
        maxArea = maxArea > area ? maxArea : area;
      }
      /** @type {number} */
      var sqw = w * w;
      /** @type {number} */
      var sqAreaSum = areaSum * areaSum;
      return Math.max(sqw * maxArea / sqAreaSum, sqAreaSum / (sqw * minArea));
    },
    /**
     * @param {Array} ch
     * @param {number} w
     * @return {?}
     */
    avgAspectRatio : function(ch, w) {
      if (!ch || ch.length == 0) {
        return Number.MAX_VALUE;
      }
      /** @type {number} */
      var sum = 0;
      /** @type {number} */
      var i = 0;
      var len = ch.length;
      for (;i < len;i++) {
        var area = ch[i]._area;
        /** @type {number} */
        var h = area / w;
        sum += w > h ? w / h : h / w;
      }
      return sum / len;
    },
    /**
     * @param {Array} ch
     * @param {number} w
     * @param {?} coord
     * @param {Object} prop
     * @return {undefined}
     */
    layoutLast : function(ch, w, coord, prop) {
      var child = ch[0];
      child.getPos(prop).setc(coord.left, coord.top);
      child.setData("width", coord.width, prop);
      child.setData("height", coord.height, prop);
    }
  };
  Layout.TM.Squarified = new Class({
    Implements : Layout.TM.Area,
    /**
     * @param {?} node
     * @param {Object} coord
     * @param {Object} prop
     * @return {undefined}
     */
    computePositions : function(node, coord, prop) {
      var config = this.config;
      /** @type {function (...[*]): number} */
      var max = Math.max;
      if (coord.width >= coord.height) {
        /** @type {string} */
        this.layout.orientation = "h";
      } else {
        /** @type {string} */
        this.layout.orientation = "v";
      }
      var ch = node.getSubnodes([1, 1], "ignore");
      if (ch.length > 0) {
        this.processChildrenLayout(node, ch, coord, prop);
        /** @type {number} */
        var i = 0;
        var l = ch.length;
        for (;i < l;i++) {
          var chi = ch[i];
          var offst = config.offset;
          /** @type {number} */
          var height = max(chi.getData("height", prop) - offst - config.titleHeight, 0);
          /** @type {number} */
          var width = max(chi.getData("width", prop) - offst, 0);
          var chipos = chi.getPos(prop);
          coord = {
            width : width,
            height : height,
            top : chipos.y + config.titleHeight,
            left : chipos.x
          };
          this.computePositions(chi, coord, prop);
        }
      }
    },
    /**
     * @param {?} dataAndEvents
     * @param {Array} ch
     * @param {Object} coord
     * @param {Object} prop
     * @return {undefined}
     */
    processChildrenLayout : function(dataAndEvents, ch, coord, prop) {
      /** @type {number} */
      var parentArea = coord.width * coord.height;
      var i;
      var l = ch.length;
      /** @type {number} */
      var totalChArea = 0;
      /** @type {Array} */
      var chArea = [];
      /** @type {number} */
      i = 0;
      for (;i < l;i++) {
        /** @type {number} */
        chArea[i] = parseFloat(ch[i].getData("area", prop));
        totalChArea += chArea[i];
      }
      /** @type {number} */
      i = 0;
      for (;i < l;i++) {
        /** @type {number} */
        ch[i]._area = parentArea * chArea[i] / totalChArea;
      }
      var minimumSideValue = this.layout.horizontal() ? coord.height : coord.width;
      ch.sort(function(b, a) {
        /** @type {number} */
        var firstByIndex = a._area - b._area;
        return firstByIndex ? firstByIndex : a.id == b.id ? 0 : a.id < b.id ? 1 : -1;
      });
      /** @type {Array} */
      var initElem = [ch[0]];
      var tail = ch.slice(1);
      this.squarify(tail, initElem, minimumSideValue, coord, prop);
    },
    /**
     * @param {string} tail
     * @param {?} initElem
     * @param {number} w
     * @param {?} coord
     * @param {Object} prop
     * @return {undefined}
     */
    squarify : function(tail, initElem, w, coord, prop) {
      this.computeDim(tail, initElem, w, coord, this.worstAspectRatio, prop);
    },
    /**
     * @param {?} opt_attributes
     * @param {number} w
     * @param {?} coord
     * @param {Object} prop
     * @return {?}
     */
    layoutRow : function(opt_attributes, w, coord, prop) {
      if (this.layout.horizontal()) {
        return this.layoutV(opt_attributes, w, coord, prop);
      } else {
        return this.layoutH(opt_attributes, w, coord, prop);
      }
    },
    /**
     * @param {?} attributes
     * @param {number} w
     * @param {?} coord
     * @param {Object} prop
     * @return {?}
     */
    layoutV : function(attributes, w, coord, prop) {
      /** @type {number} */
      var totalArea = 0;
      /**
       * @param {number} x
       * @return {?}
       */
      var rnd = function(x) {
        return x;
      };
      $.each(attributes, function(elem) {
        totalArea += elem._area;
      });
      var width = rnd(totalArea / w);
      /** @type {number} */
      var top = 0;
      /** @type {number} */
      var i = 0;
      var aLength = attributes.length;
      for (;i < aLength;i++) {
        var h = rnd(attributes[i]._area / width);
        var chi = attributes[i];
        chi.getPos(prop).setc(coord.left, coord.top + top);
        chi.setData("width", width, prop);
        chi.setData("height", h, prop);
        top += h;
      }
      var ans = {
        height : coord.height,
        width : coord.width - width,
        top : coord.top,
        left : coord.left + width
      };
      /** @type {number} */
      ans.dim = Math.min(ans.width, ans.height);
      if (ans.dim != ans.height) {
        this.layout.change();
      }
      return ans;
    },
    /**
     * @param {?} attributes
     * @param {number} w
     * @param {?} coord
     * @param {Object} prop
     * @return {?}
     */
    layoutH : function(attributes, w, coord, prop) {
      /** @type {number} */
      var totalArea = 0;
      $.each(attributes, function(elem) {
        totalArea += elem._area;
      });
      /** @type {number} */
      var height = totalArea / w;
      var top = coord.top;
      /** @type {number} */
      var left = 0;
      /** @type {number} */
      var i = 0;
      var aLength = attributes.length;
      for (;i < aLength;i++) {
        var chi = attributes[i];
        /** @type {number} */
        w = chi._area / height;
        chi.getPos(prop).setc(coord.left + left, top);
        chi.setData("width", w, prop);
        chi.setData("height", height, prop);
        left += w;
      }
      var ans = {
        height : coord.height - height,
        width : coord.width,
        top : coord.top + height,
        left : coord.left
      };
      /** @type {number} */
      ans.dim = Math.min(ans.width, ans.height);
      if (ans.dim != ans.width) {
        this.layout.change();
      }
      return ans;
    }
  });
  Layout.TM.Strip = new Class({
    Implements : Layout.TM.Area,
    /**
     * @param {?} node
     * @param {Object} coord
     * @param {Object} prop
     * @return {undefined}
     */
    computePositions : function(node, coord, prop) {
      var ch = node.getSubnodes([1, 1], "ignore");
      var config = this.config;
      /** @type {function (...[*]): number} */
      var max = Math.max;
      if (ch.length > 0) {
        this.processChildrenLayout(node, ch, coord, prop);
        /** @type {number} */
        var i = 0;
        var l = ch.length;
        for (;i < l;i++) {
          var chi = ch[i];
          var offst = config.offset;
          /** @type {number} */
          var height = max(chi.getData("height", prop) - offst - config.titleHeight, 0);
          /** @type {number} */
          var width = max(chi.getData("width", prop) - offst, 0);
          var chipos = chi.getPos(prop);
          coord = {
            width : width,
            height : height,
            top : chipos.y + config.titleHeight,
            left : chipos.x
          };
          this.computePositions(chi, coord, prop);
        }
      }
    },
    /**
     * @param {?} dataAndEvents
     * @param {Array} ch
     * @param {Object} coord
     * @param {Object} prop
     * @return {undefined}
     */
    processChildrenLayout : function(dataAndEvents, ch, coord, prop) {
      /** @type {number} */
      var parentArea = coord.width * coord.height;
      var i;
      var l = ch.length;
      /** @type {number} */
      var totalChArea = 0;
      /** @type {Array} */
      var chArea = [];
      /** @type {number} */
      i = 0;
      for (;i < l;i++) {
        /** @type {number} */
        chArea[i] = +ch[i].getData("area", prop);
        totalChArea += chArea[i];
      }
      /** @type {number} */
      i = 0;
      for (;i < l;i++) {
        /** @type {number} */
        ch[i]._area = parentArea * chArea[i] / totalChArea;
      }
      var side = this.layout.horizontal() ? coord.width : coord.height;
      /** @type {Array} */
      var initElem = [ch[0]];
      var tail = ch.slice(1);
      this.stripify(tail, initElem, side, coord, prop);
    },
    /**
     * @param {string} tail
     * @param {?} initElem
     * @param {number} w
     * @param {?} coord
     * @param {Object} prop
     * @return {undefined}
     */
    stripify : function(tail, initElem, w, coord, prop) {
      this.computeDim(tail, initElem, w, coord, this.avgAspectRatio, prop);
    },
    /**
     * @param {?} opt_attributes
     * @param {number} w
     * @param {?} coord
     * @param {Object} prop
     * @return {?}
     */
    layoutRow : function(opt_attributes, w, coord, prop) {
      if (this.layout.horizontal()) {
        return this.layoutH(opt_attributes, w, coord, prop);
      } else {
        return this.layoutV(opt_attributes, w, coord, prop);
      }
    },
    /**
     * @param {?} attributes
     * @param {number} w
     * @param {?} coord
     * @param {Object} prop
     * @return {?}
     */
    layoutV : function(attributes, w, coord, prop) {
      /** @type {number} */
      var totalArea = 0;
      $.each(attributes, function(elem) {
        totalArea += elem._area;
      });
      /** @type {number} */
      var width = totalArea / w;
      /** @type {number} */
      var top = 0;
      /** @type {number} */
      var i = 0;
      var aLength = attributes.length;
      for (;i < aLength;i++) {
        var chi = attributes[i];
        /** @type {number} */
        var h = chi._area / width;
        chi.getPos(prop).setc(coord.left, coord.top + (w - h - top));
        chi.setData("width", width, prop);
        chi.setData("height", h, prop);
        top += h;
      }
      return{
        height : coord.height,
        width : coord.width - width,
        top : coord.top,
        left : coord.left + width,
        dim : w
      };
    },
    /**
     * @param {?} attributes
     * @param {number} w
     * @param {?} coord
     * @param {Object} prop
     * @return {?}
     */
    layoutH : function(attributes, w, coord, prop) {
      /** @type {number} */
      var totalArea = 0;
      $.each(attributes, function(elem) {
        totalArea += elem._area;
      });
      /** @type {number} */
      var height = totalArea / w;
      /** @type {number} */
      var top = coord.height - height;
      /** @type {number} */
      var left = 0;
      /** @type {number} */
      var i = 0;
      var aLength = attributes.length;
      for (;i < aLength;i++) {
        var chi = attributes[i];
        /** @type {number} */
        var width = chi._area / height;
        chi.getPos(prop).setc(coord.left + left, coord.top + top);
        chi.setData("width", width, prop);
        chi.setData("height", height, prop);
        left += width;
      }
      return{
        height : coord.height - height,
        width : coord.width,
        top : coord.top,
        left : coord.left,
        dim : w
      };
    }
  });
  Layout.Icicle = new Class({
    /**
     * @param {?} adj
     * @return {undefined}
     */
    compute : function(adj) {
      adj = adj || "current";
      var from = this.graph.getNode(this.root);
      var config = this.config;
      var size = this.canvas.getSize();
      var width = size.width;
      var height = size.height;
      var offset = config.offset;
      var parentWidth = config.constrained ? config.levelsToShow : Number.MAX_VALUE;
      this.controller.onBeforeCompute(from);
      Graph.Util.computeLevels(this.graph, from.id, 0, "ignore");
      /** @type {number} */
      var treeDepth = 0;
      Graph.Util.eachLevel(from, 0, false, function(dataAndEvents, d) {
        if (d > treeDepth) {
          /** @type {number} */
          treeDepth = d;
        }
      });
      var startNode = this.graph.getNode(this.clickedNode && this.clickedNode.id || from.id);
      /** @type {number} */
      var maxDepth = Math.min(treeDepth, parentWidth - 1);
      var initialDepth = startNode._depth;
      if (this.layout.horizontal()) {
        this.computeSubtree(startNode, -width / 2, -height / 2, width / (maxDepth + 1), height, initialDepth, maxDepth, adj);
      } else {
        this.computeSubtree(startNode, -width / 2, -height / 2, width, height / (maxDepth + 1), initialDepth, maxDepth, adj);
      }
    },
    /**
     * @param {Object} root
     * @param {number} x
     * @param {number} y
     * @param {number} width
     * @param {number} height
     * @param {?} initialDepth
     * @param {number} maxDepth
     * @param {Object} prop
     * @return {undefined}
     */
    computeSubtree : function(root, x, y, width, height, initialDepth, maxDepth, prop) {
      root.getPos(prop).setc(x, y);
      root.setData("width", width, prop);
      root.setData("height", height, prop);
      var nodeLength;
      /** @type {number} */
      var K = 0;
      /** @type {number} */
      var totalDim = 0;
      var attributes = Graph.Util.getSubnodes(root, [1, 1], "ignore");
      if (!attributes.length) {
        return;
      }
      $.each(attributes, function(e) {
        totalDim += e.getData("dim");
      });
      /** @type {number} */
      var i = 0;
      var aLength = attributes.length;
      for (;i < aLength;i++) {
        if (this.layout.horizontal()) {
          /** @type {number} */
          nodeLength = height * attributes[i].getData("dim") / totalDim;
          this.computeSubtree(attributes[i], x + width, y, width, nodeLength, initialDepth, maxDepth, prop);
          y += nodeLength;
        } else {
          /** @type {number} */
          nodeLength = width * attributes[i].getData("dim") / totalDim;
          this.computeSubtree(attributes[i], x, y + height, nodeLength, height, initialDepth, maxDepth, prop);
          x += nodeLength;
        }
      }
    }
  });
  $jit.Icicle = new Class({
    Implements : [valid, Extras, Layout.Icicle],
    layout : {
      orientation : "h",
      /**
       * @return {?}
       */
      vertical : function() {
        return this.orientation == "v";
      },
      /**
       * @return {?}
       */
      horizontal : function() {
        return this.orientation == "h";
      },
      /**
       * @return {undefined}
       */
      change : function() {
        /** @type {string} */
        this.orientation = this.vertical() ? "h" : "v";
      }
    },
    /**
     * @param {?} controller
     * @return {undefined}
     */
    initialize : function(controller) {
      var config = {
        animate : false,
        orientation : "h",
        offset : 2,
        levelsToShow : Number.MAX_VALUE,
        constrained : false,
        Node : {
          type : "rectangle",
          overridable : true
        },
        Edge : {
          type : "none"
        },
        Label : {
          type : "Native"
        },
        duration : 700,
        fps : 45
      };
      var opts = Options("Canvas", "Node", "Edge", "Fx", "Tips", "NodeStyles", "Events", "Navigation", "Controller", "Label");
      this.controller = this.config = $.merge(opts, config, controller);
      this.layout.orientation = this.config.orientation;
      var canvasConfig = this.config;
      if (canvasConfig.useCanvas) {
        this.canvas = canvasConfig.useCanvas;
        /** @type {string} */
        this.config.labelContainer = this.canvas.id + "-label";
      } else {
        this.canvas = new Canvas(this, canvasConfig);
        /** @type {string} */
        this.config.labelContainer = (typeof canvasConfig.injectInto == "string" ? canvasConfig.injectInto : canvasConfig.injectInto.id) + "-label";
      }
      this.graphOptions = {
        /** @type {function (number, (number|string)): undefined} */
        klass : Vector,
        Node : {
          selected : false,
          exist : true,
          drawn : true
        }
      };
      this.graph = new Graph(this.graphOptions, this.config.Node, this.config.Edge, this.config.Label);
      this.labels = new $jit.Icicle.Label[this.config.Label.type](this);
      this.fx = new $jit.Icicle.Plot(this, $jit.Icicle);
      this.op = new $jit.Icicle.Op(this);
      this.group = new $jit.Icicle.Group(this);
      /** @type {null} */
      this.clickedNode = null;
      this.initializeExtras();
    },
    /**
     * @return {undefined}
     */
    refresh : function() {
      var type = this.config.Label.type;
      if (type != "Native") {
        var that = this;
        this.graph.eachNode(function(from) {
          that.labels.hideLabel(from, false);
        });
      }
      this.compute();
      this.plot();
    },
    /**
     * @return {undefined}
     */
    plot : function() {
      this.fx.plot(this.config);
    },
    /**
     * @param {?} node
     * @return {undefined}
     */
    enter : function(node) {
      if (this.busy) {
        return;
      }
      /** @type {boolean} */
      this.busy = true;
      var that = this;
      var config = this.config;
      var callback = {
        /**
         * @return {undefined}
         */
        onComplete : function() {
          if (config.request) {
            that.compute();
          }
          if (config.animate) {
            that.graph.nodeList.setDataset(["current", "end"], {
              alpha : [1, 0]
            });
            Graph.Util.eachSubgraph(node, function(n) {
              n.setData("alpha", 1, "end");
            }, "ignore");
            that.fx.animate({
              duration : 500,
              modes : ["node-property:alpha"],
              /**
               * @return {undefined}
               */
              onComplete : function() {
                that.clickedNode = node;
                that.compute("end");
                that.fx.animate({
                  modes : ["linear", "node-property:width:height"],
                  duration : 1E3,
                  /**
                   * @return {undefined}
                   */
                  onComplete : function() {
                    /** @type {boolean} */
                    that.busy = false;
                    that.clickedNode = node;
                  }
                });
              }
            });
          } else {
            that.clickedNode = node;
            /** @type {boolean} */
            that.busy = false;
            that.refresh();
          }
        }
      };
      if (config.request) {
        this.requestNodes(clickedNode, callback);
      } else {
        callback.onComplete();
      }
    },
    /**
     * @return {undefined}
     */
    out : function() {
      if (this.busy) {
        return;
      }
      var that = this;
      var GUtil = Graph.Util;
      var config = this.config;
      var graph = this.graph;
      var args = GUtil.getParents(graph.getNode(this.clickedNode && this.clickedNode.id || this.root));
      var parent = args[0];
      var clickedNode = parent;
      var previousClickedNode = this.clickedNode;
      /** @type {boolean} */
      this.busy = true;
      /** @type {boolean} */
      this.events.hoveredNode = false;
      if (!parent) {
        /** @type {boolean} */
        this.busy = false;
        return;
      }
      callback = {
        /**
         * @return {undefined}
         */
        onComplete : function() {
          that.clickedNode = parent;
          if (config.request) {
            that.requestNodes(parent, {
              /**
               * @return {undefined}
               */
              onComplete : function() {
                that.compute();
                that.plot();
                /** @type {boolean} */
                that.busy = false;
              }
            });
          } else {
            that.compute();
            that.plot();
            /** @type {boolean} */
            that.busy = false;
          }
        }
      };
      if (config.animate) {
        this.clickedNode = clickedNode;
        this.compute("end");
        this.clickedNode = previousClickedNode;
        this.fx.animate({
          modes : ["linear", "node-property:width:height"],
          duration : 1E3,
          /**
           * @return {undefined}
           */
          onComplete : function() {
            that.clickedNode = clickedNode;
            graph.nodeList.setDataset(["current", "end"], {
              alpha : [0, 1]
            });
            GUtil.eachSubgraph(previousClickedNode, function(n) {
              n.setData("alpha", 1);
            }, "ignore");
            that.fx.animate({
              duration : 500,
              modes : ["node-property:alpha"],
              /**
               * @return {undefined}
               */
              onComplete : function() {
                callback.onComplete();
              }
            });
          }
        });
      } else {
        callback.onComplete();
      }
    },
    /**
     * @param {?} node
     * @param {?} onComplete
     * @return {undefined}
     */
    requestNodes : function(node, onComplete) {
      var handler = $.merge(this.controller, onComplete);
      var recurring = this.config.constrained ? this.config.levelsToShow : Number.MAX_VALUE;
      if (handler.request) {
        /** @type {Array} */
        var leaves = [];
        var d = node._depth;
        Graph.Util.eachLevel(node, 0, recurring, function(n) {
          if (n.drawn && !Graph.Util.anySubnode(n)) {
            leaves.push(n);
            /** @type {number} */
            n._level = n._depth - d;
            if (this.config.constrained) {
              /** @type {number} */
              n._level = recurring - n._level;
            }
          }
        });
        this.group.requestNodes(leaves, handler);
      } else {
        handler.onComplete();
      }
    }
  });
  $jit.Icicle.Op = new Class({
    Implements : Graph.Op
  });
  $jit.Icicle.Group = new Class({
    /**
     * @param {Object} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      /** @type {Object} */
      this.viz = viz;
      this.canvas = viz.canvas;
      this.config = viz.config;
    },
    /**
     * @param {Array} nodes
     * @param {?} controller
     * @return {undefined}
     */
    requestNodes : function(nodes, controller) {
      /** @type {number} */
      var counter = 0;
      var len = nodes.length;
      var nodeSelected = {};
      /**
       * @return {undefined}
       */
      var complete = function() {
        controller.onComplete();
      };
      var viz = this.viz;
      if (len == 0) {
        complete();
      }
      /** @type {number} */
      var i = 0;
      for (;i < len;i++) {
        nodeSelected[nodes[i].id] = nodes[i];
        controller.request(nodes[i].id, nodes[i]._level, {
          /**
           * @param {number} adj
           * @param {?} lab
           * @return {undefined}
           */
          onComplete : function(adj, lab) {
            if (lab && lab.children) {
              /** @type {number} */
              lab.id = adj;
              viz.op.sum(lab, {
                type : "nothing"
              });
            }
            if (++counter == len) {
              Graph.Util.computeLevels(viz.graph, viz.root, 0);
              complete();
            }
          }
        });
      }
    }
  });
  $jit.Icicle.Plot = new Class({
    Implements : Graph.Plot,
    /**
     * @param {?} opt
     * @param {boolean} animating
     * @return {undefined}
     */
    plot : function(opt, animating) {
      opt = opt || this.viz.controller;
      var viz = this.viz;
      var graph = viz.graph;
      var root = graph.getNode(viz.clickedNode && viz.clickedNode.id || viz.root);
      var initialDepth = root._depth;
      viz.canvas.clear();
      this.plotTree(root, $.merge(opt, {
        withLabels : true,
        hideLabels : false,
        /**
         * @param {?} dataAndEvents
         * @param {Object} node
         * @return {?}
         */
        plotSubtree : function(dataAndEvents, node) {
          return!viz.config.constrained || node._depth - initialDepth < viz.config.levelsToShow;
        }
      }), animating);
    }
  });
  $jit.Icicle.Label = {};
  $jit.Icicle.Label.Native = new Class({
    Implements : Graph.Label.Native,
    /**
     * @param {?} canvas
     * @param {Object} node
     * @param {?} opt
     * @return {undefined}
     */
    renderLabel : function(canvas, node, opt) {
      var ctx = canvas.getCtx();
      var width = node.getData("width");
      var height = node.getData("height");
      var size = node.getLabelData("size");
      var bbox = ctx.measureText(node.name);
      if (height < size * 1.5 || width < bbox.width) {
        return;
      }
      var pos = node.pos.getc(true);
      ctx.fillText(node.name, pos.x + width / 2, pos.y + height / 2);
    }
  });
  $jit.Icicle.Label.SVG = new Class({
    Implements : Graph.Label.SVG,
    /**
     * @param {?} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.viz = viz;
    },
    /**
     * @param {?} from
     * @param {?} lab
     * @param {?} options
     * @return {undefined}
     */
    placeLabel : function(from, lab, options) {
      var offsetCoordinate = lab.pos.getc(true);
      var canvas = this.viz.canvas;
      var $cont = canvas.getSize();
      var tl = {
        x : Math.round(offsetCoordinate.x + $cont.width / 2),
        y : Math.round(offsetCoordinate.y + $cont.height / 2)
      };
      from.setAttribute("x", tl.x);
      from.setAttribute("y", tl.y);
      options.onPlaceLabel(from, lab);
    }
  });
  $jit.Icicle.Label.HTML = new Class({
    Implements : Graph.Label.HTML,
    /**
     * @param {?} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.viz = viz;
    },
    /**
     * @param {?} from
     * @param {?} lab
     * @param {?} options
     * @return {undefined}
     */
    placeLabel : function(from, lab, options) {
      var offsetCoordinate = lab.pos.getc(true);
      var canvas = this.viz.canvas;
      var $cont = canvas.getSize();
      var pos = {
        x : Math.round(offsetCoordinate.x + $cont.width / 2),
        y : Math.round(offsetCoordinate.y + $cont.height / 2)
      };
      var aggregateStyle = from.style;
      /** @type {string} */
      aggregateStyle.left = pos.x + "px";
      /** @type {string} */
      aggregateStyle.top = pos.y + "px";
      /** @type {string} */
      aggregateStyle.display = "";
      options.onPlaceLabel(from, lab);
    }
  });
  $jit.Icicle.Plot.NodeTypes = new Class({
    none : {
      /** @type {function (): undefined} */
      render : $.empty
    },
    rectangle : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @return {undefined}
       */
      render : function(adj, lab, event) {
        var config = this.viz.config;
        var offset = config.offset;
        var width = adj.getData("width");
        var height = adj.getData("height");
        var border = adj.getData("border");
        var pos = adj.pos.getc(true);
        var posx = pos.x + offset / 2;
        var posy = pos.y + offset / 2;
        var ctx = lab.getCtx();
        if (width - offset < 2 || height - offset < 2) {
          return;
        }
        if (config.cushion) {
          var color = adj.getData("color");
          var gradient = ctx.createRadialGradient(posx + (width - offset) / 2, posy + (height - offset) / 2, 1, posx + (width - offset) / 2, posy + (height - offset) / 2, width < height ? height : width);
          var fgcolor = $.rgbToHex($.map($.hexToRgb(color), function(dataAndEvents) {
            return dataAndEvents * 0.3 >> 0;
          }));
          gradient.addColorStop(0, color);
          gradient.addColorStop(1, fgcolor);
          ctx.fillStyle = gradient;
        }
        if (border) {
          ctx.strokeStyle = border;
          /** @type {number} */
          ctx.lineWidth = 3;
        }
        ctx.fillRect(posx, posy, Math.max(0, width - offset), Math.max(0, height - offset));
        if (border) {
          ctx.strokeRect(pos.x, pos.y, width, height);
        }
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {?}
       */
      contains : function(opt_attributes, value) {
        if (this.viz.clickedNode && !$jit.Graph.Util.isDescendantOf(opt_attributes, this.viz.clickedNode.id)) {
          return false;
        }
        var offsetCoordinate = opt_attributes.pos.getc(true);
        var actual = opt_attributes.getData("width");
        var epsilon = opt_attributes.getData("height");
        return this.nodeHelper.rectangle.contains({
          x : offsetCoordinate.x + actual / 2,
          y : offsetCoordinate.y + epsilon / 2
        }, value, actual, epsilon);
      }
    }
  });
  $jit.Icicle.Plot.EdgeTypes = new Class({
    /** @type {function (): undefined} */
    none : $.empty
  });
  Layout.ForceDirected = new Class({
    /**
     * @param {?} $allOptions
     * @return {?}
     */
    getOptions : function($allOptions) {
      var element = this.canvas.getSize();
      var originalWidth = element.width;
      var originalHeight = element.height;
      /** @type {number} */
      var count = 0;
      this.graph.eachNode(function(dataAndEvents) {
        count++;
      });
      /** @type {number} */
      var variance = originalWidth * originalHeight / count;
      /** @type {number} */
      var mult = Math.sqrt(variance);
      var ld = this.config.levelDistance;
      return{
        width : originalWidth,
        height : originalHeight,
        tstart : originalWidth * 0.1,
        /**
         * @param {number} v00
         * @return {?}
         */
        nodef : function(v00) {
          return variance / (v00 || 1);
        },
        /**
         * @param {?} value
         * @return {?}
         */
        edgef : function(value) {
          return mult * (value - ld);
        }
      };
    },
    /**
     * @param {?} adj
     * @param {?} type
     * @return {undefined}
     */
    compute : function(adj, type) {
      var lab = $.splat(adj || ["current", "start", "end"]);
      var coord = this.getOptions();
      column.compute(this.graph, lab, this.config);
      this.graph.computeLevels(this.root, 0, "ignore");
      this.graph.eachNode(function(self) {
        $.each(lab, function(prop) {
          var p = self.getPos(prop);
          if (p.equals(Vector.KER)) {
            /** @type {number} */
            p.x = coord.width / 5 * (Math.random() - 0.5);
            /** @type {number} */
            p.y = coord.height / 5 * (Math.random() - 0.5);
          }
          self.disp = {};
          $.each(lab, function(timeoutKey) {
            self.disp[timeoutKey] = getIndex(0, 0);
          });
        });
      });
      this.computePositions(lab, coord, type);
    },
    /**
     * @param {?} node
     * @param {Object} prop
     * @param {Object} p
     * @return {undefined}
     */
    computePositions : function(node, prop, p) {
      var len = this.config.iterations;
      /** @type {number} */
      var i = 0;
      var jQuery = this;
      if (p) {
        (function play() {
          var pl = p.iter;
          /** @type {number} */
          var j = 0;
          for (;j < pl;j++) {
            prop.t = prop.tstart;
            if (len) {
              prop.t *= 1 - i++ / (len - 1);
            }
            jQuery.computePositionStep(node, prop);
            if (len && i >= len) {
              p.onComplete();
              return;
            }
          }
          p.onStep(Math.round(i / (len - 1) * 100));
          setTimeout(play, 1);
        })();
      } else {
        for (;i < len;i++) {
          /** @type {number} */
          prop.t = prop.tstart * (1 - i / (len - 1));
          this.computePositionStep(node, prop);
        }
      }
    },
    /**
     * @param {?} attributes
     * @param {Object} options
     * @return {undefined}
     */
    computePositionStep : function(attributes, options) {
      var graph = this.graph;
      /** @type {function (...[*]): number} */
      var mn = Math.min;
      /** @type {function (...[*]): number} */
      var max = Math.max;
      var pos = getIndex(0, 0);
      graph.eachNode(function(node) {
        $.each(attributes, function(y) {
          /** @type {number} */
          node.disp[y].x = 0;
          /** @type {number} */
          node.disp[y].y = 0;
        });
        graph.eachNode(function(n) {
          if (n.id != node.id) {
            $.each(attributes, function(prop) {
              var p = node.getPos(prop);
              var v = n.getPos(prop);
              /** @type {number} */
              pos.x = p.x - v.x;
              /** @type {number} */
              pos.y = p.y - v.y;
              var x = pos.norm() || 1;
              node.disp[prop].$add(pos.$scale(options.nodef(x) / x));
            });
          }
        });
      });
      /** @type {boolean} */
      var T = !!graph.getNode(this.root).visited;
      graph.eachNode(function(node) {
        node.eachAdjacency(function(adj) {
          var child = adj.nodeTo;
          if (!!child.visited === T) {
            $.each(attributes, function(prop) {
              var p = node.getPos(prop);
              var v = child.getPos(prop);
              /** @type {number} */
              pos.x = p.x - v.x;
              /** @type {number} */
              pos.y = p.y - v.y;
              var udataCur = pos.norm() || 1;
              node.disp[prop].$add(pos.$scale(-options.edgef(udataCur) / udataCur));
              child.disp[prop].$add(pos.$scale(-1));
            });
          }
        });
        /** @type {boolean} */
        node.visited = !T;
      });
      var precision = options.t;
      /** @type {number} */
      var indents = options.width / 2;
      /** @type {number} */
      var minMargin = options.height / 2;
      graph.eachNode(function(event) {
        $.each(attributes, function(prop) {
          var pos = event.disp[prop];
          var I = pos.norm() || 1;
          prop = event.getPos(prop);
          prop.$add(getIndex(pos.x * mn(Math.abs(pos.x), precision) / I, pos.y * mn(Math.abs(pos.y), precision) / I));
          /** @type {number} */
          prop.x = mn(indents, max(-indents, prop.x));
          /** @type {number} */
          prop.y = mn(minMargin, max(-minMargin, prop.y));
        });
      });
    }
  });
  $jit.ForceDirected = new Class({
    Implements : [valid, Extras, Layout.ForceDirected],
    /**
     * @param {?} controller
     * @return {undefined}
     */
    initialize : function(controller) {
      var $ForceDirected = $jit.ForceDirected;
      var config = {
        iterations : 50,
        levelDistance : 50
      };
      this.controller = this.config = $.merge(Options("Canvas", "Node", "Edge", "Fx", "Tips", "NodeStyles", "Events", "Navigation", "Controller", "Label"), config, controller);
      var canvasConfig = this.config;
      if (canvasConfig.useCanvas) {
        this.canvas = canvasConfig.useCanvas;
        /** @type {string} */
        this.config.labelContainer = this.canvas.id + "-label";
      } else {
        if (canvasConfig.background) {
          canvasConfig.background = $.merge({
            type : "Circles"
          }, canvasConfig.background);
        }
        this.canvas = new Canvas(this, canvasConfig);
        /** @type {string} */
        this.config.labelContainer = (typeof canvasConfig.injectInto == "string" ? canvasConfig.injectInto : canvasConfig.injectInto.id) + "-label";
      }
      this.graphOptions = {
        /** @type {function (number, (number|string)): undefined} */
        klass : Vector,
        Node : {
          selected : false,
          exist : true,
          drawn : true
        }
      };
      this.graph = new Graph(this.graphOptions, this.config.Node, this.config.Edge);
      this.labels = new $ForceDirected.Label[canvasConfig.Label.type](this);
      this.fx = new $ForceDirected.Plot(this, $ForceDirected);
      this.op = new $ForceDirected.Op(this);
      /** @type {null} */
      this.json = null;
      /** @type {boolean} */
      this.busy = false;
      this.initializeExtras();
    },
    /**
     * @return {undefined}
     */
    refresh : function() {
      this.compute();
      this.plot();
    },
    /**
     * @return {undefined}
     */
    reposition : function() {
      this.compute("end");
    },
    /**
     * @param {?} lab
     * @return {undefined}
     */
    computeIncremental : function(lab) {
      lab = $.merge({
        iter : 20,
        property : "end",
        /** @type {function (): undefined} */
        onStep : $.empty,
        /** @type {function (): undefined} */
        onComplete : $.empty
      }, lab || {});
      this.config.onBeforeCompute(this.graph.getNode(this.root));
      this.compute(lab.property, lab);
    },
    /**
     * @return {undefined}
     */
    plot : function() {
      this.fx.plot();
    },
    /**
     * @param {?} opt_attributes
     * @return {undefined}
     */
    animate : function(opt_attributes) {
      this.fx.animate($.merge({
        modes : ["linear"]
      }, opt_attributes || {}));
    }
  });
  /** @type {boolean} */
  $jit.ForceDirected.$extend = true;
  (function(Hypertree) {
    Hypertree.Op = new Class({
      Implements : Graph.Op
    });
    Hypertree.Plot = new Class({
      Implements : Graph.Plot
    });
    Hypertree.Label = {};
    Hypertree.Label.Native = new Class({
      Implements : Graph.Label.Native
    });
    Hypertree.Label.SVG = new Class({
      Implements : Graph.Label.SVG,
      /**
       * @param {?} viz
       * @return {undefined}
       */
      initialize : function(viz) {
        this.viz = viz;
      },
      /**
       * @param {?} from
       * @param {?} lab
       * @param {?} options
       * @return {undefined}
       */
      placeLabel : function(from, lab, options) {
        var pos = lab.pos.getc(true);
        var canvas = this.viz.canvas;
        var ox = canvas.translateOffsetX;
        var oy = canvas.translateOffsetY;
        var sx = canvas.scaleOffsetX;
        var sy = canvas.scaleOffsetY;
        var $cont = canvas.getSize();
        var tl = {
          x : Math.round(pos.x * sx + ox + $cont.width / 2),
          y : Math.round(pos.y * sy + oy + $cont.height / 2)
        };
        from.setAttribute("x", tl.x);
        from.setAttribute("y", tl.y);
        options.onPlaceLabel(from, lab);
      }
    });
    Hypertree.Label.HTML = new Class({
      Implements : Graph.Label.HTML,
      /**
       * @param {?} viz
       * @return {undefined}
       */
      initialize : function(viz) {
        this.viz = viz;
      },
      /**
       * @param {?} from
       * @param {?} lab
       * @param {?} options
       * @return {undefined}
       */
      placeLabel : function(from, lab, options) {
        var pos = lab.pos.getc(true);
        var canvas = this.viz.canvas;
        var ox = canvas.translateOffsetX;
        var oy = canvas.translateOffsetY;
        var sx = canvas.scaleOffsetX;
        var sy = canvas.scaleOffsetY;
        var $cont = canvas.getSize();
        var labelPos = {
          x : Math.round(pos.x * sx + ox + $cont.width / 2),
          y : Math.round(pos.y * sy + oy + $cont.height / 2)
        };
        var style = from.style;
        /** @type {string} */
        style.left = labelPos.x + "px";
        /** @type {string} */
        style.top = labelPos.y + "px";
        /** @type {string} */
        style.display = this.fitsInCanvas(labelPos, canvas) ? "" : "none";
        options.onPlaceLabel(from, lab);
      }
    });
    Hypertree.Plot.NodeTypes = new Class({
      none : {
        /** @type {function (): undefined} */
        render : $.empty,
        contains : $.lambda(false)
      },
      circle : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var lab = adj.pos.getc(true);
          var qualifier = adj.getData("dim");
          this.nodeHelper.circle.render("fill", lab, qualifier, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("dim");
          return this.nodeHelper.circle.contains(attributes, value, actual);
        }
      },
      ellipse : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var lab = adj.pos.getc(true);
          var qualifier = adj.getData("width");
          var cycle = adj.getData("height");
          this.nodeHelper.ellipse.render("fill", lab, qualifier, cycle, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("width");
          var epsilon = opt_attributes.getData("height");
          return this.nodeHelper.ellipse.contains(attributes, value, actual, epsilon);
        }
      },
      square : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var lab = adj.pos.getc(true);
          var qualifier = adj.getData("dim");
          this.nodeHelper.square.render("fill", lab, qualifier, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("dim");
          return this.nodeHelper.square.contains(attributes, value, actual);
        }
      },
      rectangle : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var lab = adj.pos.getc(true);
          var qualifier = adj.getData("width");
          var cycle = adj.getData("height");
          this.nodeHelper.rectangle.render("fill", lab, qualifier, cycle, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("width");
          var epsilon = opt_attributes.getData("height");
          return this.nodeHelper.rectangle.contains(attributes, value, actual, epsilon);
        }
      },
      triangle : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var lab = adj.pos.getc(true);
          var qualifier = adj.getData("dim");
          this.nodeHelper.triangle.render("fill", lab, qualifier, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("dim");
          return this.nodeHelper.triangle.contains(attributes, value, actual);
        }
      },
      star : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var lab = adj.pos.getc(true);
          var qualifier = adj.getData("dim");
          this.nodeHelper.star.render("fill", lab, qualifier, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("dim");
          return this.nodeHelper.star.contains(attributes, value, actual);
        }
      }
    });
    Hypertree.Plot.EdgeTypes = new Class({
      /** @type {function (): undefined} */
      none : $.empty,
      line : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var from = adj.nodeFrom.pos.getc(true);
          var lab = adj.nodeTo.pos.getc(true);
          this.edgeHelper.line.render(from, lab, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.nodeFrom.pos.getc(true);
          var pdataOld = opt_attributes.nodeTo.pos.getc(true);
          return this.edgeHelper.line.contains(attributes, pdataOld, value, this.edge.epsilon);
        }
      },
      arrow : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var from = adj.nodeFrom.pos.getc(true);
          var lab = adj.nodeTo.pos.getc(true);
          var qualifier = adj.getData("dim");
          var direction = adj.data.$direction;
          var cycle = direction && (direction.length > 1 && direction[0] != adj.nodeFrom.id);
          this.edgeHelper.arrow.render(from, lab, qualifier, cycle, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.nodeFrom.pos.getc(true);
          var pdataOld = opt_attributes.nodeTo.pos.getc(true);
          return this.edgeHelper.arrow.contains(attributes, pdataOld, value, this.edge.epsilon);
        }
      }
    });
  })($jit.ForceDirected);
  $jit.TM = {};
  var Hypertree = $jit.TM;
  /** @type {boolean} */
  $jit.TM.$extend = true;
  Hypertree.Base = {
    layout : {
      orientation : "h",
      /**
       * @return {?}
       */
      vertical : function() {
        return this.orientation == "v";
      },
      /**
       * @return {?}
       */
      horizontal : function() {
        return this.orientation == "h";
      },
      /**
       * @return {undefined}
       */
      change : function() {
        /** @type {string} */
        this.orientation = this.vertical() ? "h" : "v";
      }
    },
    /**
     * @param {?} controller
     * @return {undefined}
     */
    initialize : function(controller) {
      var config = {
        orientation : "h",
        titleHeight : 13,
        offset : 2,
        levelsToShow : 0,
        constrained : false,
        animate : false,
        Node : {
          type : "rectangle",
          overridable : true,
          width : 3,
          height : 3,
          color : "#444"
        },
        Label : {
          textAlign : "center",
          textBaseline : "top"
        },
        Edge : {
          type : "none"
        },
        duration : 700,
        fps : 45
      };
      this.controller = this.config = $.merge(Options("Canvas", "Node", "Edge", "Fx", "Controller", "Tips", "NodeStyles", "Events", "Navigation", "Label"), config, controller);
      this.layout.orientation = this.config.orientation;
      var canvasConfig = this.config;
      if (canvasConfig.useCanvas) {
        this.canvas = canvasConfig.useCanvas;
        /** @type {string} */
        this.config.labelContainer = this.canvas.id + "-label";
      } else {
        if (canvasConfig.background) {
          canvasConfig.background = $.merge({
            type : "Circles"
          }, canvasConfig.background);
        }
        this.canvas = new Canvas(this, canvasConfig);
        /** @type {string} */
        this.config.labelContainer = (typeof canvasConfig.injectInto == "string" ? canvasConfig.injectInto : canvasConfig.injectInto.id) + "-label";
      }
      this.graphOptions = {
        /** @type {function (number, (number|string)): undefined} */
        klass : Vector,
        Node : {
          selected : false,
          exist : true,
          drawn : true
        }
      };
      this.graph = new Graph(this.graphOptions, this.config.Node, this.config.Edge);
      this.labels = new Hypertree.Label[canvasConfig.Label.type](this);
      this.fx = new Hypertree.Plot(this);
      this.op = new Hypertree.Op(this);
      this.group = new Hypertree.Group(this);
      this.geom = new Hypertree.Geom(this);
      /** @type {null} */
      this.clickedNode = null;
      /** @type {boolean} */
      this.busy = false;
      this.initializeExtras();
    },
    /**
     * @return {undefined}
     */
    refresh : function() {
      if (this.busy) {
        return;
      }
      /** @type {boolean} */
      this.busy = true;
      var that = this;
      if (this.config.animate) {
        this.compute("end");
        if (this.config.levelsToShow > 0) {
          this.geom.setRightLevelToShow(this.graph.getNode(this.clickedNode && this.clickedNode.id || this.root));
        }
        this.fx.animate($.merge(this.config, {
          modes : ["linear", "node-property:width:height"],
          /**
           * @return {undefined}
           */
          onComplete : function() {
            /** @type {boolean} */
            that.busy = false;
          }
        }));
      } else {
        var type = this.config.Label.type;
        if (type != "Native") {
          that = this;
          this.graph.eachNode(function(from) {
            that.labels.hideLabel(from, false);
          });
        }
        /** @type {boolean} */
        this.busy = false;
        this.compute();
        if (this.config.levelsToShow > 0) {
          this.geom.setRightLevelToShow(this.graph.getNode(this.clickedNode && this.clickedNode.id || this.root));
        }
        this.plot();
      }
    },
    /**
     * @return {undefined}
     */
    plot : function() {
      this.fx.plot();
    },
    /**
     * @param {?} n
     * @return {?}
     */
    leaf : function(n) {
      return n.getSubnodes([1, 1], "ignore").length == 0;
    },
    /**
     * @param {?} n
     * @return {undefined}
     */
    enter : function(n) {
      if (this.busy) {
        return;
      }
      /** @type {boolean} */
      this.busy = true;
      var that = this;
      var config = this.config;
      var graph = this.graph;
      var node = n;
      var previousClickedNode = this.clickedNode;
      var callback = {
        /**
         * @return {undefined}
         */
        onComplete : function() {
          if (config.levelsToShow > 0) {
            that.geom.setRightLevelToShow(n);
          }
          if (config.levelsToShow > 0 || config.request) {
            that.compute();
          }
          if (config.animate) {
            graph.nodeList.setData("alpha", 0, "end");
            n.eachSubgraph(function(n) {
              n.setData("alpha", 1, "end");
            }, "ignore");
            that.fx.animate({
              duration : 500,
              modes : ["node-property:alpha"],
              /**
               * @return {undefined}
               */
              onComplete : function() {
                that.clickedNode = node;
                that.compute("end");
                that.clickedNode = previousClickedNode;
                that.fx.animate({
                  modes : ["linear", "node-property:width:height"],
                  duration : 1E3,
                  /**
                   * @return {undefined}
                   */
                  onComplete : function() {
                    /** @type {boolean} */
                    that.busy = false;
                    that.clickedNode = node;
                  }
                });
              }
            });
          } else {
            /** @type {boolean} */
            that.busy = false;
            that.clickedNode = n;
            that.refresh();
          }
        }
      };
      if (config.request) {
        this.requestNodes(node, callback);
      } else {
        callback.onComplete();
      }
    },
    /**
     * @return {undefined}
     */
    out : function() {
      if (this.busy) {
        return;
      }
      /** @type {boolean} */
      this.busy = true;
      /** @type {boolean} */
      this.events.hoveredNode = false;
      var that = this;
      var config = this.config;
      var graph = this.graph;
      var args = graph.getNode(this.clickedNode && this.clickedNode.id || this.root).getParents();
      var parent = args[0];
      var clickedNode = parent;
      var previousClickedNode = this.clickedNode;
      if (!parent) {
        /** @type {boolean} */
        this.busy = false;
        return;
      }
      callback = {
        /**
         * @return {undefined}
         */
        onComplete : function() {
          that.clickedNode = parent;
          if (config.request) {
            that.requestNodes(parent, {
              /**
               * @return {undefined}
               */
              onComplete : function() {
                that.compute();
                that.plot();
                /** @type {boolean} */
                that.busy = false;
              }
            });
          } else {
            that.compute();
            that.plot();
            /** @type {boolean} */
            that.busy = false;
          }
        }
      };
      if (config.levelsToShow > 0) {
        this.geom.setRightLevelToShow(parent);
      }
      if (config.animate) {
        this.clickedNode = clickedNode;
        this.compute("end");
        this.clickedNode = previousClickedNode;
        this.fx.animate({
          modes : ["linear", "node-property:width:height"],
          duration : 1E3,
          /**
           * @return {undefined}
           */
          onComplete : function() {
            that.clickedNode = clickedNode;
            graph.eachNode(function(n) {
              n.setDataset(["current", "end"], {
                alpha : [0, 1]
              });
            }, "ignore");
            previousClickedNode.eachSubgraph(function(n) {
              n.setData("alpha", 1);
            }, "ignore");
            that.fx.animate({
              duration : 500,
              modes : ["node-property:alpha"],
              /**
               * @return {undefined}
               */
              onComplete : function() {
                callback.onComplete();
              }
            });
          }
        });
      } else {
        callback.onComplete();
      }
    },
    /**
     * @param {Array} node
     * @param {?} onComplete
     * @return {undefined}
     */
    requestNodes : function(node, onComplete) {
      var handler = $.merge(this.controller, onComplete);
      var lev = this.config.levelsToShow;
      if (handler.request) {
        /** @type {Array} */
        var leaves = [];
        var d = node._depth;
        node.eachLevel(0, lev, function(n) {
          /** @type {number} */
          var nodeLevel = lev - (n._depth - d);
          if (n.drawn && (!n.anySubnode() && nodeLevel > 0)) {
            leaves.push(n);
            /** @type {number} */
            n._level = nodeLevel;
          }
        });
        this.group.requestNodes(leaves, handler);
      } else {
        handler.onComplete();
      }
    },
    /**
     * @return {undefined}
     */
    reposition : function() {
      this.compute("end");
    }
  };
  Hypertree.Op = new Class({
    Implements : Graph.Op,
    /**
     * @param {?} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.viz = viz;
    }
  });
  Hypertree.Geom = new Class({
    Implements : Graph.Geom,
    /**
     * @return {?}
     */
    getRightLevelToShow : function() {
      return this.viz.config.levelsToShow;
    },
    /**
     * @param {?} node
     * @return {undefined}
     */
    setRightLevelToShow : function(node) {
      var y = this.getRightLevelToShow();
      var fx = this.viz.labels;
      node.eachLevel(0, y + 1, function(from) {
        /** @type {number} */
        var x = from._depth - node._depth;
        if (x > y) {
          /** @type {boolean} */
          from.drawn = false;
          /** @type {boolean} */
          from.exist = false;
          /** @type {boolean} */
          from.ignore = true;
          fx.hideLabel(from, false);
        } else {
          /** @type {boolean} */
          from.drawn = true;
          /** @type {boolean} */
          from.exist = true;
          delete from.ignore;
        }
      });
      /** @type {boolean} */
      node.drawn = true;
      delete node.ignore;
    }
  });
  Hypertree.Group = new Class({
    /**
     * @param {Object} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      /** @type {Object} */
      this.viz = viz;
      this.canvas = viz.canvas;
      this.config = viz.config;
    },
    /**
     * @param {Array} nodes
     * @param {?} controller
     * @return {undefined}
     */
    requestNodes : function(nodes, controller) {
      /** @type {number} */
      var counter = 0;
      var len = nodes.length;
      var nodeSelected = {};
      /**
       * @return {undefined}
       */
      var complete = function() {
        controller.onComplete();
      };
      var viz = this.viz;
      if (len == 0) {
        complete();
      }
      /** @type {number} */
      var i = 0;
      for (;i < len;i++) {
        nodeSelected[nodes[i].id] = nodes[i];
        controller.request(nodes[i].id, nodes[i]._level, {
          /**
           * @param {number} adj
           * @param {?} lab
           * @return {undefined}
           */
          onComplete : function(adj, lab) {
            if (lab && lab.children) {
              /** @type {number} */
              lab.id = adj;
              viz.op.sum(lab, {
                type : "nothing"
              });
            }
            if (++counter == len) {
              viz.graph.computeLevels(viz.root, 0);
              complete();
            }
          }
        });
      }
    }
  });
  Hypertree.Plot = new Class({
    Implements : Graph.Plot,
    /**
     * @param {Object} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      /** @type {Object} */
      this.viz = viz;
      this.config = viz.config;
      this.node = this.config.Node;
      this.edge = this.config.Edge;
      this.animation = new Animation;
      this.nodeTypes = new Hypertree.Plot.NodeTypes;
      this.edgeTypes = new Hypertree.Plot.EdgeTypes;
      this.labels = viz.labels;
    },
    /**
     * @param {?} opt
     * @param {boolean} animating
     * @return {undefined}
     */
    plot : function(opt, animating) {
      var viz = this.viz;
      var graph = viz.graph;
      viz.canvas.clear();
      this.plotTree(graph.getNode(viz.clickedNode && viz.clickedNode.id || viz.root), $.merge(viz.config, opt || {}, {
        withLabels : true,
        hideLabels : false,
        /**
         * @param {?} node
         * @param {Object} x
         * @return {?}
         */
        plotSubtree : function(node, x) {
          return node.anySubnode("exist");
        }
      }), animating);
    }
  });
  Hypertree.Label = {};
  Hypertree.Label.Native = new Class({
    Implements : Graph.Label.Native,
    /**
     * @param {Object} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.config = viz.config;
      this.leaf = viz.leaf;
    },
    /**
     * @param {?} canvas
     * @param {Object} node
     * @param {?} opt
     * @return {undefined}
     */
    renderLabel : function(canvas, node, opt) {
      if (!this.leaf(node) && !this.config.titleHeight) {
        return;
      }
      var pos = node.pos.getc(true);
      var ctx = canvas.getCtx();
      var width = node.getData("width");
      var constrainedHeight = node.getData("height");
      var opposite = pos.x + width / 2;
      var posY = pos.y;
      ctx.fillText(node.name, opposite, posY, width);
    }
  });
  Hypertree.Label.SVG = new Class({
    Implements : Graph.Label.SVG,
    /**
     * @param {?} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.viz = viz;
      this.leaf = viz.leaf;
      this.config = viz.config;
    },
    /**
     * @param {?} from
     * @param {?} lab
     * @param {?} options
     * @return {undefined}
     */
    placeLabel : function(from, lab, options) {
      var pos = lab.pos.getc(true);
      var canvas = this.viz.canvas;
      var ox = canvas.translateOffsetX;
      var oy = canvas.translateOffsetY;
      var sx = canvas.scaleOffsetX;
      var sy = canvas.scaleOffsetY;
      var $cont = canvas.getSize();
      var tl = {
        x : Math.round(pos.x * sx + ox + $cont.width / 2),
        y : Math.round(pos.y * sy + oy + $cont.height / 2)
      };
      from.setAttribute("x", tl.x);
      from.setAttribute("y", tl.y);
      if (!this.leaf(lab) && !this.config.titleHeight) {
        /** @type {string} */
        from.style.display = "none";
      }
      options.onPlaceLabel(from, lab);
    }
  });
  Hypertree.Label.HTML = new Class({
    Implements : Graph.Label.HTML,
    /**
     * @param {?} viz
     * @return {undefined}
     */
    initialize : function(viz) {
      this.viz = viz;
      this.leaf = viz.leaf;
      this.config = viz.config;
    },
    /**
     * @param {?} from
     * @param {?} lab
     * @param {?} options
     * @return {undefined}
     */
    placeLabel : function(from, lab, options) {
      var size = lab.pos.getc(true);
      var canvas = this.viz.canvas;
      var ox = canvas.translateOffsetX;
      var oy = canvas.translateOffsetY;
      var sx = canvas.scaleOffsetX;
      var sy = canvas.scaleOffsetY;
      var $cont = canvas.getSize();
      var pos = {
        x : Math.round(size.x * sx + ox + $cont.width / 2),
        y : Math.round(size.y * sy + oy + $cont.height / 2)
      };
      var cs = from.style;
      /** @type {string} */
      cs.left = pos.x + "px";
      /** @type {string} */
      cs.top = pos.y + "px";
      /** @type {string} */
      cs.width = lab.getData("width") * sx + "px";
      /** @type {string} */
      cs.height = lab.getData("height") * sy + "px";
      /** @type {number} */
      cs.zIndex = lab._depth * 100;
      /** @type {string} */
      cs.display = "";
      if (!this.leaf(lab) && !this.config.titleHeight) {
        /** @type {string} */
        from.style.display = "none";
      }
      options.onPlaceLabel(from, lab);
    }
  });
  Hypertree.Plot.NodeTypes = new Class({
    none : {
      /** @type {function (): undefined} */
      render : $.empty
    },
    rectangle : {
      /**
       * @param {?} adj
       * @param {?} lab
       * @param {?} event
       * @return {undefined}
       */
      render : function(adj, lab, event) {
        var orn = this.viz.leaf(adj);
        var config = this.config;
        var offst = config.offset;
        var titleHeight = config.titleHeight;
        var pos = adj.pos.getc(true);
        var width = adj.getData("width");
        var height = adj.getData("height");
        var border = adj.getData("border");
        var ctx = lab.getCtx();
        var posx = pos.x + offst / 2;
        var posy = pos.y + offst / 2;
        if (width <= offst || height <= offst) {
          return;
        }
        if (orn) {
          if (config.cushion) {
            var radgrad = ctx.createRadialGradient(posx + (width - offst) / 2, posy + (height - offst) / 2, 1, posx + (width - offst) / 2, posy + (height - offst) / 2, width < height ? height : width);
            var color = adj.getData("color");
            var colorend = $.rgbToHex($.map($.hexToRgb(color), function(dataAndEvents) {
              return dataAndEvents * 0.2 >> 0;
            }));
            radgrad.addColorStop(0, color);
            radgrad.addColorStop(1, colorend);
            ctx.fillStyle = radgrad;
          }
          ctx.fillRect(posx, posy, width - offst, height - offst);
          if (border) {
            ctx.save();
            ctx.strokeStyle = border;
            ctx.strokeRect(posx, posy, width - offst, height - offst);
            ctx.restore();
          }
        } else {
          if (titleHeight > 0) {
            ctx.fillRect(pos.x + offst / 2, pos.y + offst / 2, width - offst, titleHeight - offst);
            if (border) {
              ctx.save();
              ctx.strokeStyle = border;
              ctx.strokeRect(pos.x + offst / 2, pos.y + offst / 2, width - offst, height - offst);
              ctx.restore();
            }
          }
        }
      },
      /**
       * @param {?} opt_attributes
       * @param {?} value
       * @return {?}
       */
      contains : function(opt_attributes, value) {
        if (this.viz.clickedNode && !opt_attributes.isDescendantOf(this.viz.clickedNode.id) || opt_attributes.ignore) {
          return false;
        }
        var offsetCoordinate = opt_attributes.pos.getc(true);
        var actual = opt_attributes.getData("width");
        var leaf = this.viz.leaf(opt_attributes);
        var epsilon = leaf ? opt_attributes.getData("height") : this.config.titleHeight;
        return this.nodeHelper.rectangle.contains({
          x : offsetCoordinate.x + actual / 2,
          y : offsetCoordinate.y + epsilon / 2
        }, value, actual, epsilon);
      }
    }
  });
  Hypertree.Plot.EdgeTypes = new Class({
    /** @type {function (): undefined} */
    none : $.empty
  });
  Hypertree.SliceAndDice = new Class({
    Implements : [valid, Extras, Hypertree.Base, Layout.TM.SliceAndDice]
  });
  Hypertree.Squarified = new Class({
    Implements : [valid, Extras, Hypertree.Base, Layout.TM.Squarified]
  });
  Hypertree.Strip = new Class({
    Implements : [valid, Extras, Hypertree.Base, Layout.TM.Strip]
  });
  $jit.RGraph = new Class({
    Implements : [valid, Extras, Layout.Radial],
    /**
     * @param {?} controller
     * @return {undefined}
     */
    initialize : function(controller) {
      var $RGraph = $jit.RGraph;
      var config = {
        interpolation : "linear",
        levelDistance : 100
      };
      this.controller = this.config = $.merge(Options("Canvas", "Node", "Edge", "Fx", "Controller", "Tips", "NodeStyles", "Events", "Navigation", "Label"), config, controller);
      var canvasConfig = this.config;
      if (canvasConfig.useCanvas) {
        this.canvas = canvasConfig.useCanvas;
        /** @type {string} */
        this.config.labelContainer = this.canvas.id + "-label";
      } else {
        if (canvasConfig.background) {
          canvasConfig.background = $.merge({
            type : "Circles"
          }, canvasConfig.background);
        }
        this.canvas = new Canvas(this, canvasConfig);
        /** @type {string} */
        this.config.labelContainer = (typeof canvasConfig.injectInto == "string" ? canvasConfig.injectInto : canvasConfig.injectInto.id) + "-label";
      }
      this.graphOptions = {
        /** @type {function (number, number): undefined} */
        klass : Transform,
        Node : {
          selected : false,
          exist : true,
          drawn : true
        }
      };
      this.graph = new Graph(this.graphOptions, this.config.Node, this.config.Edge);
      this.labels = new $RGraph.Label[canvasConfig.Label.type](this);
      this.fx = new $RGraph.Plot(this, $RGraph);
      this.op = new $RGraph.Op(this);
      /** @type {null} */
      this.json = null;
      /** @type {null} */
      this.root = null;
      /** @type {boolean} */
      this.busy = false;
      /** @type {boolean} */
      this.parent = false;
      this.initializeExtras();
    },
    /**
     * @return {?}
     */
    createLevelDistanceFunc : function() {
      var ld = this.config.levelDistance;
      return function(node) {
        return(node._depth + 1) * ld;
      };
    },
    /**
     * @return {undefined}
     */
    refresh : function() {
      this.compute();
      this.plot();
    },
    /**
     * @return {undefined}
     */
    reposition : function() {
      this.compute("end");
    },
    /**
     * @return {undefined}
     */
    plot : function() {
      this.fx.plot();
    },
    /**
     * @param {?} id
     * @return {?}
     */
    getNodeAndParentAngle : function(id) {
      /** @type {boolean} */
      var theta = false;
      var node = this.graph.getNode(id);
      var codeSegments = node.getParents();
      var p = codeSegments.length > 0 ? codeSegments[0] : false;
      if (p) {
        var previous = p.pos.getc();
        var projection = node.pos.getc();
        var newPos = previous.add(projection.scale(-1));
        /** @type {number} */
        theta = Math.atan2(newPos.y, newPos.x);
        if (theta < 0) {
          theta += 2 * Math.PI;
        }
      }
      return{
        parent : p,
        theta : theta
      };
    },
    /**
     * @param {?} par
     * @param {string} id
     * @return {undefined}
     */
    tagChildren : function(par, id) {
      if (par.angleSpan) {
        /** @type {Array} */
        var adjs = [];
        par.eachAdjacency(function(elem) {
          adjs.push(elem.nodeTo);
        }, "ignore");
        /** @type {number} */
        var len = adjs.length;
        /** @type {number} */
        var i = 0;
        for (;i < len && id != adjs[i].id;i++) {
        }
        /** @type {number} */
        var j = (i + 1) % len;
        /** @type {number} */
        var k = 0;
        for (;id != adjs[j].id;j = (j + 1) % len) {
          /** @type {number} */
          adjs[j].dist = k++;
        }
      }
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @return {undefined}
     */
    onClick : function(adj, lab) {
      if (this.root != adj && !this.busy) {
        /** @type {boolean} */
        this.busy = true;
        this.root = adj;
        var that = this;
        this.controller.onBeforeCompute(this.graph.getNode(adj));
        var obj = this.getNodeAndParentAngle(adj);
        this.tagChildren(obj.parent, adj);
        this.parent = obj.parent;
        this.compute("end");
        /** @type {number} */
        var lambda = obj.theta - obj.parent.endPos.theta;
        this.graph.eachNode(function(elem) {
          elem.endPos.set(elem.endPos.getp().add($P(lambda, 0)));
        });
        var mode = this.config.interpolation;
        lab = $.merge({
          /** @type {function (): undefined} */
          onComplete : $.empty
        }, lab || {});
        this.fx.animate($.merge({
          hideLabels : true,
          modes : [mode]
        }, lab, {
          /**
           * @return {undefined}
           */
          onComplete : function() {
            /** @type {boolean} */
            that.busy = false;
            lab.onComplete();
          }
        }));
      }
    }
  });
  /** @type {boolean} */
  $jit.RGraph.$extend = true;
  (function(Hypertree) {
    Hypertree.Op = new Class({
      Implements : Graph.Op
    });
    Hypertree.Plot = new Class({
      Implements : Graph.Plot
    });
    Hypertree.Label = {};
    Hypertree.Label.Native = new Class({
      Implements : Graph.Label.Native
    });
    Hypertree.Label.SVG = new Class({
      Implements : Graph.Label.SVG,
      /**
       * @param {?} viz
       * @return {undefined}
       */
      initialize : function(viz) {
        this.viz = viz;
      },
      /**
       * @param {?} from
       * @param {?} lab
       * @param {?} options
       * @return {undefined}
       */
      placeLabel : function(from, lab, options) {
        var pos = lab.pos.getc(true);
        var canvas = this.viz.canvas;
        var ox = canvas.translateOffsetX;
        var oy = canvas.translateOffsetY;
        var sx = canvas.scaleOffsetX;
        var sy = canvas.scaleOffsetY;
        var $cont = canvas.getSize();
        var tl = {
          x : Math.round(pos.x * sx + ox + $cont.width / 2),
          y : Math.round(pos.y * sy + oy + $cont.height / 2)
        };
        from.setAttribute("x", tl.x);
        from.setAttribute("y", tl.y);
        options.onPlaceLabel(from, lab);
      }
    });
    Hypertree.Label.HTML = new Class({
      Implements : Graph.Label.HTML,
      /**
       * @param {?} viz
       * @return {undefined}
       */
      initialize : function(viz) {
        this.viz = viz;
      },
      /**
       * @param {?} from
       * @param {?} lab
       * @param {?} options
       * @return {undefined}
       */
      placeLabel : function(from, lab, options) {
        var pos = lab.pos.getc(true);
        var canvas = this.viz.canvas;
        var ox = canvas.translateOffsetX;
        var oy = canvas.translateOffsetY;
        var sx = canvas.scaleOffsetX;
        var sy = canvas.scaleOffsetY;
        var $cont = canvas.getSize();
        var labelPos = {
          x : Math.round(pos.x * sx + ox + $cont.width / 2),
          y : Math.round(pos.y * sy + oy + $cont.height / 2)
        };
        var style = from.style;
        /** @type {string} */
        style.left = labelPos.x + "px";
        /** @type {string} */
        style.top = labelPos.y + "px";
        /** @type {string} */
        style.display = this.fitsInCanvas(labelPos, canvas) ? "" : "none";
        options.onPlaceLabel(from, lab);
      }
    });
    Hypertree.Plot.NodeTypes = new Class({
      none : {
        /** @type {function (): undefined} */
        render : $.empty,
        contains : $.lambda(false)
      },
      circle : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var lab = adj.pos.getc(true);
          var qualifier = adj.getData("dim");
          this.nodeHelper.circle.render("fill", lab, qualifier, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("dim");
          return this.nodeHelper.circle.contains(attributes, value, actual);
        }
      },
      ellipse : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var lab = adj.pos.getc(true);
          var qualifier = adj.getData("width");
          var cycle = adj.getData("height");
          this.nodeHelper.ellipse.render("fill", lab, qualifier, cycle, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("width");
          var epsilon = opt_attributes.getData("height");
          return this.nodeHelper.ellipse.contains(attributes, value, actual, epsilon);
        }
      },
      square : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var lab = adj.pos.getc(true);
          var qualifier = adj.getData("dim");
          this.nodeHelper.square.render("fill", lab, qualifier, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("dim");
          return this.nodeHelper.square.contains(attributes, value, actual);
        }
      },
      rectangle : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var lab = adj.pos.getc(true);
          var qualifier = adj.getData("width");
          var cycle = adj.getData("height");
          this.nodeHelper.rectangle.render("fill", lab, qualifier, cycle, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("width");
          var epsilon = opt_attributes.getData("height");
          return this.nodeHelper.rectangle.contains(attributes, value, actual, epsilon);
        }
      },
      triangle : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var cycle = adj.pos.getc(true);
          var qualifier = adj.getData("dim");
          this.nodeHelper.triangle.render("fill", cycle, qualifier, lab);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("dim");
          return this.nodeHelper.triangle.contains(attributes, value, actual);
        }
      },
      star : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var lab = adj.pos.getc(true);
          var qualifier = adj.getData("dim");
          this.nodeHelper.star.render("fill", lab, qualifier, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.pos.getc(true);
          var actual = opt_attributes.getData("dim");
          return this.nodeHelper.star.contains(attributes, value, actual);
        }
      }
    });
    Hypertree.Plot.EdgeTypes = new Class({
      /** @type {function (): undefined} */
      none : $.empty,
      line : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var from = adj.nodeFrom.pos.getc(true);
          var lab = adj.nodeTo.pos.getc(true);
          this.edgeHelper.line.render(from, lab, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.nodeFrom.pos.getc(true);
          var pdataOld = opt_attributes.nodeTo.pos.getc(true);
          return this.edgeHelper.line.contains(attributes, pdataOld, value, this.edge.epsilon);
        }
      },
      arrow : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var from = adj.nodeFrom.pos.getc(true);
          var lab = adj.nodeTo.pos.getc(true);
          var qualifier = adj.getData("dim");
          var direction = adj.data.$direction;
          var cycle = direction && (direction.length > 1 && direction[0] != adj.nodeFrom.id);
          this.edgeHelper.arrow.render(from, lab, qualifier, cycle, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var attributes = opt_attributes.nodeFrom.pos.getc(true);
          var pdataOld = opt_attributes.nodeTo.pos.getc(true);
          return this.edgeHelper.arrow.contains(attributes, pdataOld, value, this.edge.epsilon);
        }
      }
    });
  })($jit.RGraph);
  /**
   * @param {?} c
   * @return {?}
   */
  Vector.prototype.moebiusTransformation = function(c) {
    var num = this.add(c);
    var den = c.$conjugate().$prod(this);
    den.x++;
    return num.$div(den);
  };
  /**
   * @param {?} graph
   * @param {Array} pos
   * @param {Array} array
   * @param {Event} key
   * @param {string} flags
   * @return {undefined}
   */
  Graph.Util.moebiusTransformation = function(graph, pos, array, key, flags) {
    this.eachNode(graph, function(obj) {
      /** @type {number} */
      var i = 0;
      for (;i < array.length;i++) {
        var p = pos[i].scale(-1);
        var prop = key ? key : array[i];
        obj.getPos(array[i]).set(obj.getPos(prop).getc().moebiusTransformation(p));
      }
    }, flags);
  };
  $jit.Hypertree = new Class({
    Implements : [valid, Extras, Layout.Radial],
    /**
     * @param {?} controller
     * @return {undefined}
     */
    initialize : function(controller) {
      var $Hypertree = $jit.Hypertree;
      var config = {
        radius : "auto",
        offset : 0,
        Edge : {
          type : "hyperline"
        },
        duration : 1500,
        fps : 35
      };
      this.controller = this.config = $.merge(Options("Canvas", "Node", "Edge", "Fx", "Tips", "NodeStyles", "Events", "Navigation", "Controller", "Label"), config, controller);
      var canvasConfig = this.config;
      if (canvasConfig.useCanvas) {
        this.canvas = canvasConfig.useCanvas;
        /** @type {string} */
        this.config.labelContainer = this.canvas.id + "-label";
      } else {
        if (canvasConfig.background) {
          canvasConfig.background = $.merge({
            type : "Circles"
          }, canvasConfig.background);
        }
        this.canvas = new Canvas(this, canvasConfig);
        /** @type {string} */
        this.config.labelContainer = (typeof canvasConfig.injectInto == "string" ? canvasConfig.injectInto : canvasConfig.injectInto.id) + "-label";
      }
      this.graphOptions = {
        /** @type {function (number, number): undefined} */
        klass : Transform,
        Node : {
          selected : false,
          exist : true,
          drawn : true
        }
      };
      this.graph = new Graph(this.graphOptions, this.config.Node, this.config.Edge);
      this.labels = new $Hypertree.Label[canvasConfig.Label.type](this);
      this.fx = new $Hypertree.Plot(this, $Hypertree);
      this.op = new $Hypertree.Op(this);
      /** @type {null} */
      this.json = null;
      /** @type {null} */
      this.root = null;
      /** @type {boolean} */
      this.busy = false;
      this.initializeExtras();
    },
    /**
     * @return {?}
     */
    createLevelDistanceFunc : function() {
      var r = this.getRadius();
      /** @type {number} */
      var depth = 0;
      /** @type {function (...[*]): number} */
      var max = Math.max;
      var config = this.config;
      this.graph.eachNode(function(node) {
        /** @type {number} */
        depth = max(node._depth, depth);
      }, "ignore");
      depth++;
      /**
       * @param {number} a
       * @return {?}
       */
      var genDistFunc = function(a) {
        return function(node) {
          node.scale = r;
          var d = node._depth + 1;
          /** @type {number} */
          var acum = 0;
          /** @type {function (*, *): number} */
          var pow = Math.pow;
          for (;d;) {
            acum += pow(a, d--);
          }
          return acum - config.offset;
        };
      };
      /** @type {number} */
      var i = 0.51;
      for (;i <= 1;i += 0.01) {
        /** @type {number} */
        var y = (1 - Math.pow(i, depth)) / (1 - i);
        if (y >= 2) {
          return genDistFunc(i - 0.01);
        }
      }
      return genDistFunc(0.75);
    },
    /**
     * @return {?}
     */
    getRadius : function() {
      var rad = this.config.radius;
      if (rad !== "auto") {
        return rad;
      }
      var ul = this.canvas.getSize();
      return Math.min(ul.width, ul.height) / 2;
    },
    /**
     * @param {boolean} dataAndEvents
     * @return {undefined}
     */
    refresh : function(dataAndEvents) {
      if (dataAndEvents) {
        this.reposition();
        this.graph.eachNode(function(node) {
          node.startPos.rho = node.pos.rho = node.endPos.rho;
          node.startPos.theta = node.pos.theta = node.endPos.theta;
        });
      } else {
        this.compute();
      }
      this.plot();
    },
    /**
     * @return {undefined}
     */
    reposition : function() {
      this.compute("end");
      var vector = this.graph.getNode(this.root).pos.getc().scale(-1);
      Graph.Util.moebiusTransformation(this.graph, [vector], ["end"], "end", "ignore");
      this.graph.eachNode(function(node) {
        if (node.ignore) {
          node.endPos.rho = node.pos.rho;
          node.endPos.theta = node.pos.theta;
        }
      });
    },
    /**
     * @return {undefined}
     */
    plot : function() {
      this.fx.plot();
    },
    /**
     * @param {?} adj
     * @param {?} lab
     * @return {undefined}
     */
    onClick : function(adj, lab) {
      var to = this.graph.getNode(adj).pos.getc(true);
      this.move(to, lab);
    },
    /**
     * @param {?} pos
     * @param {Object} opt
     * @return {undefined}
     */
    move : function(pos, opt) {
      var versor = getIndex(pos.x, pos.y);
      if (this.busy === false && versor.norm() < 1) {
        /** @type {boolean} */
        this.busy = true;
        var from = this.graph.getClosestNodeToPos(versor);
        var that = this;
        this.graph.computeLevels(from.id, 0);
        this.controller.onBeforeCompute(from);
        opt = $.merge({
          /** @type {function (): undefined} */
          onComplete : $.empty
        }, opt || {});
        this.fx.animate($.merge({
          modes : ["moebius"],
          hideLabels : true
        }, opt, {
          /**
           * @return {undefined}
           */
          onComplete : function() {
            /** @type {boolean} */
            that.busy = false;
            opt.onComplete();
          }
        }), versor);
      }
    }
  });
  /** @type {boolean} */
  $jit.Hypertree.$extend = true;
  (function(Hypertree) {
    Hypertree.Op = new Class({
      Implements : Graph.Op
    });
    Hypertree.Plot = new Class({
      Implements : Graph.Plot
    });
    Hypertree.Label = {};
    Hypertree.Label.Native = new Class({
      Implements : Graph.Label.Native,
      /**
       * @param {?} viz
       * @return {undefined}
       */
      initialize : function(viz) {
        this.viz = viz;
      },
      /**
       * @param {?} canvas
       * @param {Object} node
       * @param {?} opt
       * @return {undefined}
       */
      renderLabel : function(canvas, node, opt) {
        var ctx = canvas.getCtx();
        var coord = node.pos.getc(true);
        var s = this.viz.getRadius();
        ctx.fillText(node.name, coord.x * s, coord.y * s);
      }
    });
    Hypertree.Label.SVG = new Class({
      Implements : Graph.Label.SVG,
      /**
       * @param {?} viz
       * @return {undefined}
       */
      initialize : function(viz) {
        this.viz = viz;
      },
      /**
       * @param {?} from
       * @param {?} lab
       * @param {?} options
       * @return {undefined}
       */
      placeLabel : function(from, lab, options) {
        var pos = lab.pos.getc(true);
        var canvas = this.viz.canvas;
        var ox = canvas.translateOffsetX;
        var oy = canvas.translateOffsetY;
        var sx = canvas.scaleOffsetX;
        var sy = canvas.scaleOffsetY;
        var $cont = canvas.getSize();
        var r = this.viz.getRadius();
        var tl = {
          x : Math.round(pos.x * sx * r + ox + $cont.width / 2),
          y : Math.round(pos.y * sy * r + oy + $cont.height / 2)
        };
        from.setAttribute("x", tl.x);
        from.setAttribute("y", tl.y);
        options.onPlaceLabel(from, lab);
      }
    });
    Hypertree.Label.HTML = new Class({
      Implements : Graph.Label.HTML,
      /**
       * @param {?} viz
       * @return {undefined}
       */
      initialize : function(viz) {
        this.viz = viz;
      },
      /**
       * @param {?} from
       * @param {?} lab
       * @param {?} options
       * @return {undefined}
       */
      placeLabel : function(from, lab, options) {
        var pos = lab.pos.getc(true);
        var canvas = this.viz.canvas;
        var ox = canvas.translateOffsetX;
        var oy = canvas.translateOffsetY;
        var sx = canvas.scaleOffsetX;
        var sy = canvas.scaleOffsetY;
        var $cont = canvas.getSize();
        var r = this.viz.getRadius();
        var labelPos = {
          x : Math.round(pos.x * sx * r + ox + $cont.width / 2),
          y : Math.round(pos.y * sy * r + oy + $cont.height / 2)
        };
        var style = from.style;
        /** @type {string} */
        style.left = labelPos.x + "px";
        /** @type {string} */
        style.top = labelPos.y + "px";
        /** @type {string} */
        style.display = this.fitsInCanvas(labelPos, canvas) ? "" : "none";
        options.onPlaceLabel(from, lab);
      }
    });
    Hypertree.Plot.NodeTypes = new Class({
      none : {
        /** @type {function (): undefined} */
        render : $.empty,
        contains : $.lambda(false)
      },
      circle : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var node = this.node;
          var qualifier = adj.getData("dim");
          var cycle = adj.pos.getc();
          qualifier = node.transform ? qualifier * (1 - cycle.squaredNorm()) : qualifier;
          cycle.$scale(adj.scale);
          if (qualifier > 0.2) {
            this.nodeHelper.circle.render("fill", cycle, qualifier, lab);
          }
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var actual = opt_attributes.getData("dim");
          var attributes = opt_attributes.pos.getc().$scale(opt_attributes.scale);
          return this.nodeHelper.circle.contains(attributes, value, actual);
        }
      },
      ellipse : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var cycle = adj.pos.getc().$scale(adj.scale);
          var qualifier = adj.getData("width");
          var fix = adj.getData("height");
          this.nodeHelper.ellipse.render("fill", cycle, qualifier, fix, lab);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var actual = opt_attributes.getData("width");
          var epsilon = opt_attributes.getData("height");
          var attributes = opt_attributes.pos.getc().$scale(opt_attributes.scale);
          return this.nodeHelper.circle.contains(attributes, value, actual, epsilon);
        }
      },
      square : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var node = this.node;
          var qualifier = adj.getData("dim");
          var cycle = adj.pos.getc();
          qualifier = node.transform ? qualifier * (1 - cycle.squaredNorm()) : qualifier;
          cycle.$scale(adj.scale);
          if (qualifier > 0.2) {
            this.nodeHelper.square.render("fill", cycle, qualifier, lab);
          }
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var actual = opt_attributes.getData("dim");
          var attributes = opt_attributes.pos.getc().$scale(opt_attributes.scale);
          return this.nodeHelper.square.contains(attributes, value, actual);
        }
      },
      rectangle : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var node = this.node;
          var qualifier = adj.getData("width");
          var fix = adj.getData("height");
          var cycle = adj.pos.getc();
          qualifier = node.transform ? qualifier * (1 - cycle.squaredNorm()) : qualifier;
          fix = node.transform ? fix * (1 - cycle.squaredNorm()) : fix;
          cycle.$scale(adj.scale);
          if (qualifier > 0.2 && fix > 0.2) {
            this.nodeHelper.rectangle.render("fill", cycle, qualifier, fix, lab);
          }
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var actual = opt_attributes.getData("width");
          var epsilon = opt_attributes.getData("height");
          var attributes = opt_attributes.pos.getc().$scale(opt_attributes.scale);
          return this.nodeHelper.rectangle.contains(attributes, value, actual, epsilon);
        }
      },
      triangle : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var node = this.node;
          var qualifier = adj.getData("dim");
          var cycle = adj.pos.getc();
          qualifier = node.transform ? qualifier * (1 - cycle.squaredNorm()) : qualifier;
          cycle.$scale(adj.scale);
          if (qualifier > 0.2) {
            this.nodeHelper.triangle.render("fill", cycle, qualifier, lab);
          }
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var actual = opt_attributes.getData("dim");
          var attributes = opt_attributes.pos.getc().$scale(opt_attributes.scale);
          return this.nodeHelper.triangle.contains(attributes, value, actual);
        }
      },
      star : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var node = this.node;
          var qualifier = adj.getData("dim");
          var cycle = adj.pos.getc();
          qualifier = node.transform ? qualifier * (1 - cycle.squaredNorm()) : qualifier;
          cycle.$scale(adj.scale);
          if (qualifier > 0.2) {
            this.nodeHelper.star.render("fill", cycle, qualifier, lab);
          }
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {?}
         */
        contains : function(opt_attributes, value) {
          var actual = opt_attributes.getData("dim");
          var attributes = opt_attributes.pos.getc().$scale(opt_attributes.scale);
          return this.nodeHelper.star.contains(attributes, value, actual);
        }
      }
    });
    Hypertree.Plot.EdgeTypes = new Class({
      /** @type {function (): undefined} */
      none : $.empty,
      line : {
        /**
         * @param {?} adj
         * @param {?} type
         * @return {undefined}
         */
        render : function(adj, type) {
          var to = adj.nodeFrom.pos.getc(true);
          var from = adj.nodeTo.pos.getc(true);
          var r = adj.nodeFrom.scale;
          this.edgeHelper.line.render({
            x : to.x * r,
            y : to.y * r
          }, {
            x : from.x * r,
            y : from.y * r
          }, type);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {undefined}
         */
        contains : function(opt_attributes, value) {
          var to = opt_attributes.nodeFrom.pos.getc(true);
          var from = opt_attributes.nodeTo.pos.getc(true);
          var r = opt_attributes.nodeFrom.scale;
          this.edgeHelper.line.contains({
            x : to.x * r,
            y : to.y * r
          }, {
            x : from.x * r,
            y : from.y * r
          }, value, this.edge.epsilon);
        }
      },
      arrow : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var to = adj.nodeFrom.pos.getc(true);
          var from = adj.nodeTo.pos.getc(true);
          var r = adj.nodeFrom.scale;
          var qualifier = adj.getData("dim");
          var direction = adj.data.$direction;
          var cycle = direction && (direction.length > 1 && direction[0] != adj.nodeFrom.id);
          this.edgeHelper.arrow.render({
            x : to.x * r,
            y : to.y * r
          }, {
            x : from.x * r,
            y : from.y * r
          }, qualifier, cycle, lab);
        },
        /**
         * @param {?} opt_attributes
         * @param {?} value
         * @return {undefined}
         */
        contains : function(opt_attributes, value) {
          var to = opt_attributes.nodeFrom.pos.getc(true);
          var from = opt_attributes.nodeTo.pos.getc(true);
          var r = opt_attributes.nodeFrom.scale;
          this.edgeHelper.arrow.contains({
            x : to.x * r,
            y : to.y * r
          }, {
            x : from.x * r,
            y : from.y * r
          }, value, this.edge.epsilon);
        }
      },
      hyperline : {
        /**
         * @param {?} adj
         * @param {?} lab
         * @return {undefined}
         */
        render : function(adj, lab) {
          var from = adj.nodeFrom.pos.getc();
          var cycle = adj.nodeTo.pos.getc();
          var qualifier = this.viz.getRadius();
          this.edgeHelper.hyperline.render(from, cycle, qualifier, lab);
        },
        contains : $.lambda(false)
      }
    });
  })($jit.Hypertree);
})();
</script>
<!-- Example File -->
<script>

var labelType, useGradients, nativeTextSupport, animate;

(function() {
  var ua = navigator.userAgent,
      iStuff = ua.match(/iPhone/i) || ua.match(/iPad/i),
      typeOfCanvas = typeof HTMLCanvasElement,
      nativeCanvasSupport = (typeOfCanvas == \'object\' || typeOfCanvas == \'function\'),
      textSupport = nativeCanvasSupport
        && (typeof document.createElement(\'canvas\').getContext(\'2d\').fillText == \'function\');
  //I\'m setting this based on the fact that ExCanvas provides text support for IE
  //and that as of today iPhone/iPad current text support is lame
  labelType = (!nativeCanvasSupport || (textSupport && !iStuff))? \'Native\' : \'HTML\';
  nativeTextSupport = labelType == \'Native\';
  useGradients = nativeCanvasSupport;
  animate = !(iStuff || !nativeCanvasSupport);
})();

var Log = {
  elem: false,
  write: function(text){
    if (!this.elem)
      this.elem = document.getElementById(\'log\');
    this.elem.innerHTML = text;
    this.elem.style.left = (500 - this.elem.offsetWidth / 2) + \'px\';
  }
};


function init(){
    //init data
    var json = __data_will_locate_here__;
    //end
    var infovis = document.getElementById(\'infovis\');
    var w = infovis.offsetWidth - 50, h = infovis.offsetHeight - 50;

    //init Hypertree
    var ht = new $jit.Hypertree({
      //id of the visualization container
      injectInto: \'infovis\',
      //canvas width and height
      width: w,
      height: h,
      //Change node and edge styles such as
      //color, width and dimensions.
      Node: {
          dim: 9,
          color: "#f00"
      },
      Edge: {
          lineWidth: 2,
          color: "#088"
      },
      onBeforeCompute: function(node){
          Log.write("centering");
      },
      //Attach event handlers and add text to the
      //labels. This method is only triggered on label
      //creation
      onCreateLabel: function(domElement, node){
          domElement.innerHTML = node.name;
          $jit.util.addEvent(domElement, \'click\', function () {
              ht.onClick(node.id, {
                  onComplete: function() {
                      ht.controller.onComplete();
                  }
              });
          });
      },
      //Change node styles when labels are placed
      //or moved.
      onPlaceLabel: function(domElement, node){
          var style = domElement.style;
          style.display = \'\';
          style.cursor = \'pointer\';
          if (node._depth <= 1) {
              style.fontSize = "0.8em";
              style.color = "#ddd";

          } else if(node._depth == 2){
              style.fontSize = "0.7em";
              style.color = "#555";

          } else {
              style.display = \'none\';
          }

          var left = parseInt(style.left);
          var w = domElement.offsetWidth;
          style.left = (left - w / 2) + \'px\';
      },

      onComplete: function(){
          Log.write("Network Map");

          //Build the right column relations list.
          //This is done by collecting the information (stored in the data property)
          //for all the nodes adjacent to the centered node.
          var node = ht.graph.getClosestNodeToOrigin("current");
          var html = "<h4>" + node.name + "</h4><b>Connections:</b>";
          html += "<ul>";
          node.eachAdjacency(function(adj){
              var child = adj.nodeTo;
              if (child.data) {
                  var rel = (child.data.band == node.name) ? child.data.relation : node.data.relation;
                  html += "<li>" + child.name + " " + "<div class=\\"relation\\">(relation: " + rel + ")</div></li>";
              }
          });
          html += "</ul>";
          $jit.id(\'inner-details\').innerHTML = html;
      }
    });
    //load JSON data.
    ht.loadJSON(json);
    //compute positions and plot.
    ht.refresh();
    //end
    ht.controller.onComplete();
}
</script>
</head>

<body onload="init();">
<div id="container">

<div id="left-container">



        <div class="text">
        <h4>
__title_to_replace__
        </h4>
<h5>__description_to_replace__</h5>

        </div>

        <div id="id-list"></div>


<div style="text-align:center;"></div>
</div>

<div id="center-container">
    <div id="infovis"></div>
</div>

<div id="right-container">

<div id="inner-details"></div>

</div>

<div id="log"></div>
</div>
</body>
</html>'''.replace('__data_will_locate_here__', json.dumps(dgraph)) \
        .replace('__title_to_replace__', messages(language, "pentest_graphs")) \
        .replace('__description_to_replace__', messages(language, "graph_message")) \
        .replace('__html_title_to_replace__', messages(language, "nettacker_report"))
    if version() is 2:
        return data.decode('utf8')
    return data
