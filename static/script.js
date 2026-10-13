/**
 * Retrieves the CSRF token from the meta tag, cookie, or form input.
 */
function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta && meta.content) return meta.content;
  const cookieMatch = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
  if (cookieMatch) return decodeURIComponent(cookieMatch[1]);
  const input = document.querySelector('input[name="csrf_token"]');
  if (input && input.value) return input.value;
  return "";
}

window.getCsrfToken = getCsrfToken;

/**
 * Resets all loading spinners and re-enables submit buttons across all forms.
 */
function resetSpinnersAndButtons() {
  document.querySelectorAll(".spinner").forEach((s) => {
    s.style.display = "none";
  });
  document.querySelectorAll('button[type="submit"]').forEach((btn) => {
    btn.disabled = false;
    btn.style.opacity = "";
    btn.style.cursor = "";
  });
}

window.resetSpinnersAndButtons = resetSpinnersAndButtons;

/**
 * Shows the loading spinner and disables submit button upon valid form submission.
 * Preserves browser validation behavior and prevents duplicate submissions.
 */
function showSpinner(formId, spinnerId) {
  let form = typeof formId === "string" ? document.getElementById(formId) : formId;
  if (!form && window.event && window.event.target) {
    form = window.event.target.closest("form");
  }

  // If form has client-side validation errors, let the browser show warnings and do not activate spinner
  if (form && typeof form.checkValidity === "function" && !form.checkValidity()) {
    return false;
  }

  const spinner = typeof spinnerId === "string" ? document.getElementById(spinnerId) : spinnerId;
  if (spinner) {
    spinner.style.display = "block";
  }

  if (form) {
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
      // Defer disabling slightly to allow standard form submission initiation
      setTimeout(() => {
        submitBtn.disabled = true;
      }, 10);
    }

    // Safety timeout: Reset spinner and button after 20 seconds so form is never stuck indefinitely
    setTimeout(() => {
      resetSpinnersAndButtons();
    }, 20000);
  }

  return true;
}

window.showSpinner = showSpinner;

// Reset spinner and submit button if restored via browser bfcache
window.addEventListener("pageshow", resetSpinnersAndButtons);

document.addEventListener("DOMContentLoaded", async () => {
  // Ensure all spinners are hidden and buttons are enabled whenever page loads or re-renders
  resetSpinnersAndButtons();
  const loginBtn = document.querySelector(".login-btn");
  const dashboardLinks = document.querySelectorAll('a[href="/dashboard"]');

  async function checkSession() {
    try {
      const response = await fetch("/api/user/check_session", {
        method: "GET",
        credentials: "include",
      });
      const data = await response.json();

      if (data.logged_in) {
        localStorage.setItem("isLoggedIn", "true");
        localStorage.setItem("userEmail", data.email);
        if (loginBtn) {
          loginBtn.innerHTML = "<strong>Logout</strong>";
          loginBtn.href = "#";
        }
      } else {
        localStorage.removeItem("isLoggedIn");
        localStorage.removeItem("userEmail");
        if (loginBtn) {
          loginBtn.innerHTML = "<strong>Login</strong>";
          loginBtn.href = "/login";
        }
      }
    } catch (err) {
      console.error("Session check failed:", err);
    }
  }

  await checkSession();

  if (loginBtn) {
    loginBtn.addEventListener("click", async (e) => {
      if (localStorage.getItem("isLoggedIn") === "true") {
        e.preventDefault();
        try {
          const response = await fetch("/api/user/logout", {
            method: "POST",
            headers: {
              "X-CSRFToken": getCsrfToken(),
            },
            credentials: "include",
          });
          const data = await response.json();
          if (response.ok) {
            alert(data.message);
            localStorage.removeItem("isLoggedIn");
            localStorage.removeItem("userEmail");
            window.location.reload();
          }
        } catch (err) {
          console.error("Logout failed:", err);
        }
      }
    });
  }

  dashboardLinks.forEach(link => {
    link.addEventListener("click", (e) => {
      if (localStorage.getItem("isLoggedIn") !== "true") {
        e.preventDefault();
        alert("Please login to access the dashboard.");
      }
    });
  });
});

