$(function () {
  $('[data-toggle="tooltip"]').tooltip()
})

// Simplified Dark Mode Toggle
$(document).ready(function() {
  // Set dark mode as default
  if (!localStorage.getItem('theme')) {
    localStorage.setItem('theme', 'dark');
  }
  
  const currentTheme = localStorage.getItem('theme');
  if (currentTheme === 'dark') {
    $('body').attr('data-theme', 'dark');
    $('#themeIcon').removeClass('fa-moon-o').addClass('fa-sun-o');
  }
  
  $('#themeToggle').click(function() {
    if ($('body').attr('data-theme') === 'dark') {
      $('body').removeAttr('data-theme');
      $('#themeIcon').removeClass('fa-sun-o').addClass('fa-moon-o');
      localStorage.setItem('theme', 'light');
    } else {
      $('body').attr('data-theme', 'dark');
      $('#themeIcon').removeClass('fa-moon-o').addClass('fa-sun-o');
      localStorage.setItem('theme', 'dark');
    }
  });
});

// Simplified Search with hardcoded posts
$(document).ready(function() {
  const posts = [
    {
      title: '[HTB] Interface',
      url: '/2025/06/27/HTB-Interface.html',
      excerpt: 'Medium difficulty HTB machine involving dompdf RCE vulnerability and privilege escalation.',
      tags: 'htb medium linux dompdf rce vulnerability'
    },
    {
      title: 'First Entry', 
      url: '/2025/06/27/First-Entry.html',
      excerpt: 'Welcome to my ethical hacking blog',
      tags: 'blog welcome introduction'
    },
    {
      title: '[HTB] Shoppy',
      url: '/2025/07/02/HTB-Shoppy.html',
      excerpt: 'Easy difficulty HTB machine involving NoSQL injection, Mattermost foothold, and Docker privilege escalation.',
      tags: 'htb easy linux nosql mattermost docker privilege escalation'
    }
  ];
  
  $('#searchInput').on('input', function() {
    const query = $(this).val().toLowerCase();
    const results = $('#searchResults');
    
    if (query.length < 2) {
      results.hide();
      return;
    }
    
    const matches = posts.filter(post => 
      post.title.toLowerCase().includes(query) ||
      post.excerpt.toLowerCase().includes(query) ||
      post.tags.toLowerCase().includes(query)
    );
    
    if (matches.length > 0) {
      const html = matches.map(post => 
        `<div class="search-result-item" onclick="window.location.href='${post.url}'">
          <div class="search-result-title">${post.title}</div>
          <div class="search-result-excerpt">${post.excerpt}</div>
         </div>`
      ).join('');
      results.html(html).show();
    } else {
      results.html('<div class="search-result-item">No results found</div>').show();
    }
  });
  
  // Hide search results when clicking outside
  $(document).click(function(e) {
    if (!$(e.target).closest('.search-container').length) {
      $('#searchResults').hide();
    }
  });
  
  // Handle enter key
  $('#searchInput').keydown(function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      const firstResult = $('#searchResults .search-result-item').first();
      if (firstResult.length) {
        firstResult.click();
      }
    }
  });
});

// Add smooth scrolling for anchor links
$(document).ready(function() {
  $('a[href^="#"]').click(function(e) {
    e.preventDefault();
    const target = $(this.getAttribute('href'));
    if (target.length) {
      $('html, body').stop().animate({
        scrollTop: target.offset().top - 100
      }, 800);
    }
  });
});

// Add CSS for search result highlighting
const searchStyles = `
<style>
mark {
  background-color: var(--link-color);
  color: white;
  padding: 2px 4px;
  border-radius: 3px;
  font-weight: bold;
}

.search-result-meta {
  font-size: 11px;
  opacity: 0.6;
  margin-top: 5px;
}

.search-result-meta small {
  color: var(--text-color);
}
</style>
`;

// Inject search styles
document.addEventListener('DOMContentLoaded', function() {
  document.head.insertAdjacentHTML('beforeend', searchStyles);
});


