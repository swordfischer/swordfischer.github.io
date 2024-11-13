---
layout: base
title: "Writeups"
---
<div class="home">
  {%- if page.title -%}
    <h1 class="page-heading">{{ page.title }}</h1>
    <hr>
  {%- endif -%}
  {% for collection in site.collections %}
    {% if site[collection.label].size > 0 %}
      <h2 class="post-list-heading">{{ collection.name }}</h2>
      <ul class="post-list">
        {%- assign date_format = site.minima.date_format | default: "%b %-d, %Y" -%}
        {%- assign items = site[collection.label] | sort: 'date' | reverse -%}
        {% for item in items %}
        <li>
          <span class="post-meta">{{ item.date | date: date_format }}</span>
          <span class="post-meta {{ item.difficulty | downcase }}">{{ item.difficulty }}</span>
          {% if item.type == "CTF" %}
          <span class="post-meta post-category">({{ item.ctf_category }})</span>
          {% endif %}
          <h3>
            <a class="post-link" href="{{ item.url | relative_url }}">
              {{ item.title | escape }}
            </a>
          </h3>
        </li>
        {% endfor %}
      </ul>
      <hr>
    {% endif %}
  {% endfor %}

</div>