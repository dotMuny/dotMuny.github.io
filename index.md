---
layout: home
title: "Welcome Hacker"
---

## Recent Posts

<ul>
  {% for post in site.posts %}
    {% if "posts" in post.tags %}
      <li><a href="{{ post.url | relative_url }}">{{ post.title }}</a></li>
    {% endif %}
  {% endfor %}
</ul>
