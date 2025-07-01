$(function () {
  $('[data-toggle="tooltip"]').tooltip()
})

// Dark Mode Toggle Functionality
document.addEventListener('DOMContentLoaded', function() {
  const themeToggle = document.getElementById('themeToggle');
  const themeIcon = document.getElementById('themeIcon');
  const body = document.body;
  
  // Check for saved theme preference or default to 'dark' mode
  const currentTheme = localStorage.getItem('theme') || 'dark';
  
  // Apply the saved theme
  if (currentTheme === 'dark') {
    body.setAttribute('data-theme', 'dark');
    themeIcon.className = 'fa fa-sun-o';
  } else {
    body.removeAttribute('data-theme');
    themeIcon.className = 'fa fa-moon-o';
  }
  
  // Theme toggle event listener
  themeToggle.addEventListener('click', function() {
    const currentTheme = body.getAttribute('data-theme');
    
    if (currentTheme === 'dark') {
      body.removeAttribute('data-theme');
      themeIcon.className = 'fa fa-moon-o';
      localStorage.setItem('theme', 'light');
    } else {
      body.setAttribute('data-theme', 'dark');
      themeIcon.className = 'fa fa-sun-o';
      localStorage.setItem('theme', 'dark');
    }
  });
});

// Search Functionality
class BlogSearch {
  constructor() {
    this.searchInput = document.getElementById('searchInput');
    this.searchResults = document.getElementById('searchResults');
    this.posts = [];
    this.isLoading = false;
    
    this.init();
  }
  
  async init() {
    if (this.searchInput) {
      await this.loadPosts();
      this.bindEvents();
    }
  }
  
  async loadPosts() {
    try {
      this.isLoading = true;
      
      // Try to fetch posts from Jekyll's generated posts data
      try {
        const response = await fetch('/assets/data/posts.json');
        if (response.ok) {
          this.posts = await response.json();
        } else {
          throw new Error('Posts data not found');
        }
      } catch (fetchError) {
        // Fallback to hardcoded posts if fetch fails
        console.log('Using fallback posts data');
        this.posts = [
          {
            title: '[HTB] Interface',
            url: '/2025/06/27/HTB-Interface.html',
            date: '2025-06-27',
            tags: ['htb', 'medium', 'linux'],
            excerpt: 'Medium difficulty HTB machine involving dompdf RCE vulnerability and privilege escalation.',
            content: 'htb interface linux dompdf rce vulnerability exploitation pentesting'
          },
          {
            title: 'First Entry',
            url: '/2025/06/27/First-Entry.html',
            date: '2025-06-27',
            tags: ['blog'],
            excerpt: 'Welcome to my ethical hacking blog',
            content: 'welcome first entry blog ethical hacking cybersecurity'
          }
        ];
      }
      
      this.isLoading = false;
    } catch (error) {
      console.error('Error loading posts:', error);
      this.isLoading = false;
    }
  }
  
  bindEvents() {
    // Search input event
    this.searchInput.addEventListener('input', (e) => {
      const query = e.target.value.trim();
      if (query.length >= 2) {
        this.performSearch(query);
      } else {
        this.hideResults();
      }
    });
    
    // Hide results when clicking outside
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.search-container')) {
        this.hideResults();
      }
    });
    
    // Prevent form submission on enter
    this.searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        const firstResult = this.searchResults.querySelector('.search-result-item');
        if (firstResult) {
          window.location.href = firstResult.dataset.url;
        }
      }
    });
  }
  
  performSearch(query) {
    if (this.isLoading) return;
    
    const results = this.posts.filter(post => {
      const searchText = `${post.title} ${post.excerpt} ${post.content} ${post.tags.join(' ')}`.toLowerCase();
      return searchText.includes(query.toLowerCase());
    });
    
    this.displayResults(results, query);
  }
  
  displayResults(results, query) {
    if (results.length === 0) {
      this.searchResults.innerHTML = '<div class="search-result-item">No results found</div>';
    } else {
      this.searchResults.innerHTML = results.map(post => {
        return `
          <div class="search-result-item" data-url="${post.url}">
            <div class="search-result-title">${this.highlightQuery(post.title, query)}</div>
            <div class="search-result-excerpt">${this.highlightQuery(post.excerpt, query)}</div>
            <div class="search-result-meta">
              <small>${post.date} • ${post.tags.map(tag => `#${tag}`).join(' ')}</small>
            </div>
          </div>
        `;
      }).join('');
      
      // Add click handlers to results
      this.searchResults.querySelectorAll('.search-result-item').forEach(item => {
        item.addEventListener('click', () => {
          const url = item.dataset.url;
          if (url) {
            window.location.href = url;
          }
        });
      });
    }
    
    this.showResults();
  }
  
  highlightQuery(text, query) {
    if (!query) return text;
    const regex = new RegExp(`(${query})`, 'gi');
    return text.replace(regex, '<mark>$1</mark>');
  }
  
  showResults() {
    this.searchResults.style.display = 'block';
  }
  
  hideResults() {
    this.searchResults.style.display = 'none';
  }
}

// Initialize search when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  new BlogSearch();
});



// Add smooth scrolling for anchor links
document.addEventListener('DOMContentLoaded', function() {
  const links = document.querySelectorAll('a[href^="#"]');
  
  links.forEach(link => {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      
      const targetId = this.getAttribute('href');
      const targetElement = document.querySelector(targetId);
      
      if (targetElement) {
        targetElement.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
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


