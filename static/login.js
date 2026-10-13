function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta && meta.content) return meta.content;
  const cookieMatch = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
  if (cookieMatch) return decodeURIComponent(cookieMatch[1]);
  const input = document.querySelector('input[name="csrf_token"]');
  if (input && input.value) return input.value;
  return "";
}

document.addEventListener("DOMContentLoaded", () => {
  const toggleBtn = document.getElementById("toggleFormBtn");
  const formTitle = document.getElementById("formTitle");
  const welcomeTitle = document.getElementById("welcomeTitle");
  const welcomeText = document.getElementById("welcomeText");

  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");

  const loginBtn = document.getElementById("loginBtn");
  const logoutBtn = document.getElementById("logoutBtn");

  let showingRegister = false;

  
  toggleBtn.addEventListener("click", () => {
    showingRegister = !showingRegister;
    if (showingRegister) {
      formTitle.textContent = "Register";
      welcomeTitle.textContent = "Welcome Back!";
      welcomeText.textContent = "Already have an account?";
      toggleBtn.textContent = "Login";
      loginForm.style.display = "none";
      registerForm.style.display = "block";
    } else {
      formTitle.textContent = "Login";
      welcomeTitle.textContent = "Hello, Welcome!";
      welcomeText.textContent = "Don't have an account?";
      toggleBtn.textContent = "Register";
      loginForm.style.display = "block";
      registerForm.style.display = "none";
    }
  });

  
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
        if (loginBtn && logoutBtn) {
          loginBtn.style.display = "none";
          logoutBtn.style.display = "block";
        }
      } else {
        localStorage.removeItem("isLoggedIn");
        localStorage.removeItem("userEmail");
        if (loginBtn && logoutBtn) {
          loginBtn.style.display = "block";
          logoutBtn.style.display = "none";
        }
      }
    } catch (err) {
      console.error("Session check failed:", err);
    }
  }

  checkSession(); 

  
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = document.getElementById("loginEmail").value.trim();
    const password = document.getElementById("loginPassword").value.trim();

    if (!email || !password) {
      alert("Please fill in all fields!");
      return;
    }

    try {
      const response = await fetch("/api/user/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCsrfToken(),
        },
        credentials: "include",
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();
      if (response.ok) {
        alert(data.message);
        localStorage.setItem("isLoggedIn", "true");
        localStorage.setItem("userEmail", email);
        window.location.href = "/";
      } else {
        alert(data.error || "Login failed.");
      }
    } catch (err) {
      alert("Server error: " + err.message);
    }
  });

  
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const name = document.getElementById("regName").value.trim();
    const email = document.getElementById("regEmail").value.trim();
    const password = document.getElementById("regPassword").value.trim();
    const contact = document.getElementById("regContact").value.trim();

    if (!name || !email || !password) {
      alert("Please fill in all required fields!");
      return;
    }

    try {
      const response = await fetch("/api/user/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCsrfToken(),
        },
        credentials: "include",
        body: JSON.stringify({ name, email, password, contact }),
      });

      const data = await response.json();
      if (response.ok) {
        alert(data.message);
        toggleBtn.click(); 
      } else {
        alert(data.error || "Registration failed.");
      }
    } catch (err) {
      alert("Server error: " + err.message);
    }
  });

  
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
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
        alert("Server error: " + err.message);
      }
    });
  }
});
