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
      url: '/cybersecurity/2025/07/03/IoT-Auditing.html',
      excerpt: 'Comprehensive guide to IoT security auditing methodologies, tools, and best practices for identifying vulnerabilities.',
      tags: 'cybersecurity iot security auditing penetration testing methodology vulnerability assessment'
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
      url: '/tools/2025/09/26/Penelope.html',
      excerpt: 'Penelope is a lightweight Python reverse-shell handler that stabilises shells, manages sessions and provides file transfer utilities — a practical ergonomics boost for pentesters and CTF players.',
      tags: 'security tools pentesting revshell python oscp'
    },
    {
      title: '[HTB] Baby',
      url: '/2025/09/29/HTB-Baby.html',
      excerpt: 'Easy AD/Windows DC box — LDAP enumeration exposed user metadata and an initial password; password-spray and a netexec password-change yielded Caroline.Robinson WinRM access. SeBackupPrivilege + DiskShadow were used to dump NTDS.dit and extract the Administrator hash (secretsdump), enabling full domain compromise via Evil-WinRM. Clean chain: LDAP enum → password spray/change → WinRM foothold → DiskShadow/NTDS dump → Administrator shell.',
      tags: 'htb easy windows active-directory ldap password-spray netexec change-password winrm evil-winrm sebackup diskshadow ntds.dit secretsdump credential-dump domain-compromise'
    },
    {
      title: 'The Value of CTFs for Learning Cybersecurity',
      url: '/cybersecurity/2025/10/01/The-Value-of-CTFs-for-Learning-Cybersecurity.html',
      excerpt: 'How Capture The Flag competitions build real-world hacking skills. Explore why CTFs are one of the most effective ways to develop pentesting abilities, learn offensive security, and prepare for certifications like OSCP.',
      tags: 'cybersecurity ctf capture-the-flag hack-the-box htb tryhackme pentesting learning offensive-security oscp training hands-on education'
    },
    {
      title: '[HTB] BabyTwo',
      url: '/2025/10/03/HTB-BabyTwo.html',
      excerpt: 'A guest-friendly DC leaks a logon script in SYSVOL; poisoning it pops a user shell, BloodHound shows ACL control over a GPO admin account, and pyGPOAbuse turns that into local Administrators and full compromise.',
      tags: 'htb windows active-directory smb rid-cycling bloodhound sysvol logon-script powerview acls gpo pygpoabuse winrm hackthebox'
    },
    {
      title: '[HTB] Delegate',
      url: '/2025/10/04/HTB-Delegate.html',
      excerpt: 'Medium HTB AD machine: SMB guest share leaks creds via a login script → BloodHound shows GenericWrite over a user; targeted Kerberoast yields password and WinRM shell; create a rogue computer, enable unconstrained delegation, coerce the DC (PrinterBug) to capture its TGT; DCSync to dump Administrator’s hash.',
      tags: 'htb medium windows active-directory smb guest-share creds-leak bloodhound genericwrite targeted-kerberoast kerberoast winrm addcomputer unconstrained-delegation krbrelayx printerbug coercion dcsync privilege-escalation'
    },
    {
      title: "How Apple's MagSafe Wireless Charging Works",
      url: '/hardware/2025/10/05/How-Apples-MagSafe-Wireless-Charging-Works.html',
      excerpt: 'Engineering deep dive into MagSafe: inductive power, magnet alignment, higher-frequency drive (~360 kHz), Qi protocol with Apple extensions, efficiency, and safety considerations compared to standard Qi.',
      tags: 'hardware wireless-charging magsafe qi qi2 induction coils magnets ferrite nfc power-delivery efficiency apple'
    },
    {
      title: '[HTB] Manage',
      url: '/2025/10/06/HTB-Manage.html',
      excerpt: 'Easy HTB machine pivoting from exposed JMX/RMI on Tomcat to code execution with beanshooter, then leveraging dumped Tomcat credentials and a world-readable backup containing Google Authenticator data to beat 2FA and assume useradmin. A constrained sudo rule for adduser let me create an admin user whose group mapped to full sudo, yielding root.',
      tags: 'htb easy linux tomcat jmx rmi beanshooter rce reverse-shell google-authenticator 2fa backup-codes password-reuse sudo adduser privilege-escalation'
    },
    {
      title: 'uv: Astral’s High-Performance Python Package Manager',
      url: '/software/2025/10/07/uv-Astrals-High-Performance-Python-Package-Manager.html',
      excerpt: 'Deep dive into uv, a Rust-powered, fast package manager for Python with lockfiles, caching, and environment management.',
      tags: 'software python packaging uv pip pip-tools virtualenv pyenv performance lockfile ci'
    },
    {
      title: '[HTB] Lock',
      url: '/2025/10/08/HTB-Lock.html',
      excerpt: 'Easy Windows HTB where a leaked Gitea personal access token in an old commit enabled API access to a private website repo wired to CI/CD. I pushed an ASPX webshell to get a shell as Ellen, looted an mRemoteNG config from Documents to decrypt Gales RDP creds, then abused PDF24 Creators MSI repair flow with an oplock on its log to hold a SYSTEM console and pop a SYSTEM cmd (CI/CD webshell → mRemoteNG creds → RDP → PDF24 repair + oplock → SYSTEM).',
      tags: 'htb easy windows gitea token-leak cicd aspx webshell reverse-shell swagger mremoteng rdp pdf24 cve-2023-49147 oplock msiexec privilege-escalation'
    },
    {
      title: 'What OPSEC Really Is: Beyond InfoSec, Personal Cybersecurity, and Privacy',
      url: '/opsec/2025/10/08/What-OPSEC-Really-Is.html',
      excerpt: 'Discover what OPSEC really is and how it extends far beyond InfoSec and privacy. Learn the 5 core principles, real-world examples, and practical applications of Operational Security for individuals and organizations in the digital age.',
      tags: 'cybersecurity opsec operational-security privacy infosec personal-security digital-hygiene threat-modeling security-awareness behavioral-security'
    },
    {
      title: '[HTB] Down',
      url: '/2025/10/20/HTB-Down.html',
      excerpt: 'Easy HTB Linux machine. SSRF by abusing curl’s multi-URL support to read local files and recover source, revealing a TCP “expert mode”. A port parameter validation bug allowed netcat **parameter injection** (`-e /bin/bash`) for a www-data shell. Local loot included a `pswm` vault; mirroring its `cryptocode.decrypt` call with rockyou popped the master key and user password. `sudo ALL` on the user made root trivial.',
      tags: 'htb easy linux ssrf curl multi-url file-read php source-disclosure netcat parameter-injection reverse-shell pswm cryptocode rockyou su ssh sudo-all privilege-escalation'
    },
    {
      title: '[HTB] Reset',
      url: '/2025/11/03/HTB-Reset.html',
      excerpt: 'Easy HTB Linux machine. Forgot password endpoint leaked temporary credentials enabling dashboard access. Log poisoning via Apache access.log User-Agent field yielded a www-data reverse shell. Lateral movement via Rservices (rlogin) using hosts.equiv trust, then privilege escalation leveraging sudo nano access to drop a root shell.',
      tags: 'htb easy linux forgot-password log-poisoning apache access.log user-agent rservices rlogin hosts.equiv lateral-movement sudo nano privilege-escalation'
    },
    {
      title: '[HTB] Outbound',
      url: '/2025/11/15/HTB-Outbound.html',
      excerpt: 'Easy HTB Linux machine. Roundcube webmail RCE (CVE-2025-49113) via Metasploit yielded www-data shell. Password reuse enabled lateral movement to tyler, then database credentials revealed jacob password. Decrypted Roundcube session data using DES3 key to extract jacob credentials. SSH access as jacob, then symlink attack on writable log file (/var/log/below/error_root.log) to overwrite /etc/passwd and gain root access.',
      tags: 'htb easy linux roundcube webmail rce cve-2025-49113 metasploit meterpreter password-reuse database credentials des3 decryption ssh symlink attack privilege-escalation /etc/passwd'
    },
    {
      title: '[HTB] Academy',
      url: '/2025/11/17/HTB-Academy.html',
      excerpt: 'Easy HTB Linux machine. Web fuzzing revealed admin.php; modifying roleid parameter during registration granted admin access, exposing a Laravel staging subdomain. Laravel CVE-2018-15133 token unserialize RCE using exposed APP_KEY yielded a www-data shell. Lateral movement via .env database credentials to cry0l1t3, then aureport audit logs revealed mrb3n password. Privilege escalation through sudo composer GTFOBins technique.',
      tags: 'htb easy linux laravel cve-2018-15133 token-unserialize rce app-key reverse-shell env-credentials lateral-movement aureport audit-logs sudo composer privilege-escalation'
    },
    {
      title: '[HTB] Mirage',
      url: '/2025/11/22/HTB-Mirage.html',
      excerpt: 'Hard HTB AD machine. NFS share revealed DNS misconfiguration for nats-svc. DNS spoofing and fake NATS server captured Dev_Account_A credentials. NATS consumer revealed david.jjackson credentials. Kerberoasting yielded nathan.aadam password. BloodHound showed ForceChangePassword chain: mark.bbond → javier.mmarshall → ReadGMSAPassword on Mirage-Service$. ESC10 abuse via weak certificate mapping (Schannel) enabled UPN manipulation, certificate enrollment, and RBCD to compromise domain controller via secretsdump.',
      tags: 'htb hard windows active-directory nfs dns-spoofing nats-server credential-capture kerberoasting bloodhound forcechangepassword gmsa esc10 certificate-mapping schannel upn-manipulation certipy-ad rbcd s4u2 secretsdump domain-compromise'
    },
    {
      title: 'Vishing',
      url: '/2025/11/22/Vishing.html',
      excerpt: 'Defending against real-time AI vishing attacks powered by voice cloning. Learn how attackers use just 3 seconds of audio to impersonate voices, why technical detection fails, and practical countermeasures including verification phrases and multi-factor authentication.',
      tags: 'cybersecurity vishing voice-phishing ai deepfake voice-cloning social-engineering vall-e sovits real-time-synthesis verification-phrases multi-factor-authentication security-awareness'
    },
    {
      title: '[HTB] Voleur',
      url: '/2025/11/23/HTB-Voleur.html',
      excerpt: 'Medium HTB AD machine. SMB enumeration revealed encrypted Excel file with credentials; BloodHound showed WriteSPN permission enabling targeted Kerberoast to crack svc_winrm password. Lateral movement via RESTORE USERS group to recover deleted AD user (todd.wolfe), DPAPI decryption revealed jeremy.combs credentials. WSL access via SSH key allowed NTDS.dit dump from backups, secretsdump extracted Administrator hash for domain compromise.',
      tags: 'htb medium windows active-directory smb kerberos bloodhound writespn targeted-kerberoast kerberoast evil-winrm restore-users deleted-objects dpapi credential-decryption wsl ssh ntds.dit secretsdump domain-compromise'
    },
    {
      title: '[HTB] RustyKey',
      url: '/2025/11/23/HTB-RustyKey.html',
      excerpt: 'Hard HTB AD machine. LDAP enumeration and BloodHound revealed attack paths. Timeroasting attack extracted computer account password (IT-COMPUTER3$). Machine account added itself to HELPDESK group, removed IT from Protected Objects, changed bb.morgan password. Lateral movement to ee.reed via RunasCs, COM hijacking for privilege escalation, unconstrained delegation configuration. S4U2 impersonation of backupadmin for domain admin access.',
      tags: 'htb hard windows active-directory ldap bloodhound timeroasting ntp computer-account bloodyad helpdesk protected-objects lateral-movement runascs com-hijacking unconstrained-delegation s4u2 impersonation domain-admin'
    },
    {
      title: '[HTB] Era',
      url: '/2025/11/29/HTB-Era.html',
      excerpt: 'Medium HTB Linux machine. Subdomain enumeration revealed file.era.htb with file upload functionality. IDOR vulnerability in download.php allowed access to SQLite backup containing bcrypt password hashes. Password cracking with John the Ripper yielded yuri and eric credentials. SSH2 stream wrapper exploitation via IDOR enabled reverse shell as eric. Privilege escalation by replacing /opt/AV/periodic-checks/monitor binary with backdoored version, copying signature section to bypass integrity checks, and executing SUID bash.',
      tags: 'htb medium linux subdomain-enumeration idor sqlite backup bcrypt john-the-ripper password-cracking ssh2 stream-wrapper reverse-shell privilege-escalation binary-replacement signature-bypass suid bash'
    },
    {
      title: '[HTB] RetroTwo',
      url: '/2025/12/05/HTB-RetroTwo.html',
      excerpt: 'Easy HTB AD machine. SMB guest access revealed an Access database file; password cracking with John the Ripper yielded ldapreader credentials. BloodHound showed PRE-WINDOWS 2000 COMPATIBLE ACCESS group membership for FS01, allowing password reset via bloodyAD. ADMWS01$ account manipulation added ldapreader to Services group for RDP access. Zerologon (CVE-2020-1472) exploitation enabled domain controller compromise via secretsdump.',
      tags: 'htb easy windows active-directory smb guest-access access-database john-the-ripper ldapreader bloodhound pre-windows-2000-compatible-access bloodyad password-reset services-group rdp zerologon cve-2020-1472 secretsdump domain-compromise'
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
  
  // Initialize animated counter after posts array is defined
  initAnimatedCounter(posts);
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

// ============================================
// ANIMATED COUNTER FOR HOME PAGE
// ============================================
function initAnimatedCounter(postsArray) {
  // Only run on home page
  if ($('.stats-counter').length) {
    // Count writeups and posts from the posts array
    const writeups = postsArray.filter(post => post.title.startsWith('[HTB]'));
    const regularPosts = postsArray.filter(post => !post.title.startsWith('[HTB]'));
    
    const writeupsCount = writeups.length;
    const postsCount = regularPosts.length;
    
    // Animate counters
    animateCounter('#writeupsCount', writeupsCount);
    animateCounter('#postsCount', postsCount);
  }
}

function animateCounter(selector, targetValue) {
  const element = $(selector);
  const duration = 1500; // 1.5 seconds
  const startTime = Date.now();
  
  function updateCounter() {
    const elapsed = Date.now() - startTime;
    const progress = Math.min(elapsed / duration, 1);
    
    // Use easing function for smooth animation
    const easeOutQuart = 1 - Math.pow(1 - progress, 4);
    const currentValue = Math.floor(easeOutQuart * targetValue);
    
    element.text(currentValue);
    
    if (progress < 1) {
      requestAnimationFrame(updateCounter);
    } else {
      element.text(targetValue); // Ensure final value is exact
    }
  }
  
  requestAnimationFrame(updateCounter);
}


