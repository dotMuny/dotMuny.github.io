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
    },
    {
      title: 'IoT Auditing',
      url: '/2025/07/03/IoT-Auditing.html',
      excerpt: 'Comprehensive guide to IoT security auditing methodologies, tools, and best practices for identifying vulnerabilities.',
      tags: 'iot security auditing penetration testing methodology vulnerability assessment'
    },
    {
      title: '[HTB] Love',
      url: '/2025/07/04/HTB-Love.html',
      excerpt: 'Easy difficulty HTB machine featuring SSRF vulnerability and privilege escalation through AlwaysInstallElevated.',
      tags: 'htb easy windows ssrf privilege escalation msi'
    },
    {
      title: '[HTB] Jeeves',
      url: '/2025/07/05/HTB-Jeeves.html',
      excerpt: 'Medium difficulty HTB machine involving Jenkins exploitation and Windows privilege escalation.',
      tags: 'htb medium windows jenkins privilege escalation keepass'
    },
    {
      title: '[HTB] CrossFitTwo',
      url: '/2025/07/08/HTB-CrossFitTwo.html',
      excerpt: 'Insane difficulty HTB machine running OpenBSD with web exploitation, Unbound DNS control, and advanced privilege escalation.',
      tags: 'htb insane openbsd web exploitation unbound dns privilege escalation'
    },
    {
      title: '[HTB] Tabby',
      url: '/2025/07/10/HTB-Tabby.html',
      excerpt: 'Easy difficulty HTB machine featuring LFI vulnerability, Apache Tomcat exploitation, and privilege escalation through file permissions.',
      tags: 'htb easy linux ubuntu apache tomcat lfi path traversal war webshell privilege escalation'
    },
    {
      title: '[HTB] RedPanda',
      url: '/2025/07/15/HTB-RedPanda.html',
      excerpt: 'Easy difficulty HTB machine featuring Spring Boot application, SSTI vulnerability, and privilege escalation through log injection.',
      tags: 'htb easy linux ubuntu spring boot java apache tomcat ssti log injection privilege escalation'
    },
    {
      title: '[HTB] Time',
      url: '/2025/07/16/HTB-Time.html',
      excerpt: 'Medium difficulty HTB machine featuring Jackson deserialization vulnerability, H2 database exploitation, and systemd timer privilege escalation.',
      tags: 'htb medium linux ubuntu jackson deserialization h2 database json validator cve-2019-12384 systemd timer privilege escalation'
    },
    {
      title: '[HTB] Forgotten',
      url: '/2025/09/26/HTB-Forgotten.html',
      excerpt: 'Easy HTB machine exploiting a vulnerable LimeSurvey installation — installer allowed plugin upload and RCE (reverse shell). Credentials leaked in environment variables enabled SSH access, and a writable host mount combined with a SUID bash trick yielded root. Clean, container-based escalation flow (LimeSurvey RCE → SSH foothold → SUID root shell).',
      tags: 'htb easy linux limesurvey rce plugin-upload reverse-shell env-credentials ssh container mount sudo suid-bash privilege-escalation'
    },
    {
      title: 'Penelope',
      url: '/2025/09/26/HTB-Penelope',
      excerpt: 'Penelope is a lightweight Python reverse-shell handler that stabilises shells, manages sessions and provides file transfer utilities — a practical ergonomics boost for pentesters and CTF players.',
      tags: 'security tools pentesting revshell python oscp'
    },
    {
      title: '[HTB] Baby',
      url: '/2025/09/29/HTB-Baby.html',
      excerpt: 'Easy AD/Windows DC box — LDAP enumeration exposed user metadata and an initial password; password-spray and a netexec password-change yielded Caroline.Robinson WinRM access. SeBackupPrivilege + DiskShadow were used to dump NTDS.dit and extract the Administrator hash (secretsdump), enabling full domain compromise via Evil-WinRM. Clean chain: LDAP enum → password spray/change → WinRM foothold → DiskShadow/NTDS dump → Administrator shell.',
      tags: 'htb easy windows active-directory ldap password-spray netexec change-password winrm evil-winrm sebackup diskshadow ntds.dit secretsdump credential-dump domain-compromise'
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

// Table of Contents Generator
$(document).ready(function() {
  // Only run on post pages that have the TOC sidebar
  if ($('#toc').length && $('.post-content').length) {
    generateTableOfContents();
    setupTocScrollSpy();
  }
});

function generateTableOfContents() {
  const tocContainer = $('#toc');
  const postContent = $('.post-content');
  const headers = postContent.find('h1, h2, h3, h4, h5, h6');
  
  if (headers.length === 0) {
    tocContainer.html('<p class="text-muted small">No headings found</p>');
    return;
  }
  
  let tocHTML = '<ul>';
  let currentLevel = 1;
  
  headers.each(function(index) {
    const header = $(this);
    const level = parseInt(header.prop('tagName').charAt(1));
    const text = header.text().trim();
    const id = 'toc-' + text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    
    // Add ID to header for linking
    header.attr('id', id);
    
    // Handle nesting levels
    if (level > currentLevel) {
      for (let i = currentLevel; i < level; i++) {
        tocHTML += '<ul>';
      }
    } else if (level < currentLevel) {
      for (let i = currentLevel; i > level; i--) {
        tocHTML += '</ul></li>';
      }
    } else if (index > 0) {
      tocHTML += '</li>';
    }
    
    tocHTML += `<li><a href="#${id}" class="toc-link" data-target="${id}">${text}</a>`;
    currentLevel = level;
  });
  
  // Close remaining tags
  for (let i = currentLevel; i >= 1; i--) {
    tocHTML += '</li>';
  }
  tocHTML += '</ul>';
  
  tocContainer.html(tocHTML);
  
  // Add click handlers for smooth scrolling
  $('.toc-link').click(function(e) {
    e.preventDefault();
    const target = $(this).data('target');
    const targetElement = $('#' + target);
    
    if (targetElement.length) {
      $('html, body').animate({
        scrollTop: targetElement.offset().top - 100
      }, 500);
    }
  });
}

function setupTocScrollSpy() {
  const tocLinks = $('.toc-link');
  const headers = $('.post-content h1, .post-content h2, .post-content h3, .post-content h4, .post-content h5, .post-content h6');
  
  if (headers.length === 0) return;
  
  $(window).scroll(function() {
    let current = '';
    const scrollTop = $(window).scrollTop();
    
    headers.each(function() {
      const header = $(this);
      const headerTop = header.offset().top - 120;
      
      if (scrollTop >= headerTop) {
        current = header.attr('id');
      }
    });
    
    // Update active state
    tocLinks.removeClass('active');
    if (current) {
      $(`.toc-link[data-target="${current}"]`).addClass('active');
    }
  });
  
  // Trigger scroll event on page load
  $(window).trigger('scroll');
}

// ============================================
// BACK TO TOP BUTTON
// ============================================
$(document).ready(function() {
  // Create back to top button
  const backToTopButton = $('<button id="backToTop" class="back-to-top" title="Back to Top"><i class="fas fa-arrow-up"></i></button>');
  $('body').append(backToTopButton);
  
  // Show/hide button based on scroll position
  $(window).scroll(function() {
    if ($(this).scrollTop() > 300) {
      $('#backToTop').addClass('show');
    } else {
      $('#backToTop').removeClass('show');
    }
  });
  
  // Scroll to top when clicked
  $('#backToTop').click(function() {
    $('html, body').animate({ scrollTop: 0 }, 600);
    return false;
  });
});

// ============================================
// READING PROGRESS BAR
// ============================================
$(document).ready(function() {
  // Only show on post pages
  if ($('.post-content').length || $('article').length) {
    // Create progress bar
    const progressBar = $('<div class="reading-progress"><div class="reading-progress-fill"></div></div>');
    $('body').prepend(progressBar);
    
    // Update progress on scroll
    $(window).scroll(function() {
      const winHeight = $(window).height();
      const docHeight = $(document).height();
      const scrollTop = $(window).scrollTop();
      const progress = (scrollTop / (docHeight - winHeight)) * 100;
      
      $('.reading-progress-fill').css('width', progress + '%');
    });
  }
});


