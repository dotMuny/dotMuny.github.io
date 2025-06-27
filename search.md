---
layout: default
title: "Search"
permalink: /search/
---

<div id="search-container">
  <input type="text" id="search-input" placeholder="Buscar...">
  <ul id="results-container"></ul>
</div>

<script src="https://unpkg.com/simple-jekyll-search@latest/dest/simple-jekyll-search.min.js"></script>
<script>
  SimpleJekyllSearch({
    searchInput: document.getElementById('search-input'),
    resultsContainer: document.getElementById('results-container'),
    json: '/search.json'
  });
</script>
