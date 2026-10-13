function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta && meta.content) return meta.content;
  const cookieMatch = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
  if (cookieMatch) return decodeURIComponent(cookieMatch[1]);
  const input = document.querySelector('input[name="csrf_token"]');
  if (input && input.value) return input.value;
  return "";
}

document.addEventListener("DOMContentLoaded", async () => {
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
