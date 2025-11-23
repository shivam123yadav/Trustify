document.addEventListener("DOMContentLoaded", async () => {
  const userName = document.getElementById("userName");
  const userEmail = document.getElementById("userEmail");
  const userPhoto = document.getElementById("userPhoto");
  const historyTable = document.getElementById("historyTable");
  const logoutBtn = document.getElementById("logoutBtn");

  try {
    const res = await fetch("/api/user/check_session", {
      method: "GET",
      credentials: "include",
    });

    const data = await res.json();

    if (!data.logged_in) {
      alert("Please login first!");
      window.location.href = "/login";
      return;
    }
    const profileRes = await fetch("/api/user/profile_data", {
      method: "GET",
      credentials: "include",
    });

    const profileData = await profileRes.json();
    const user = profileData.user;
    const history = profileData.history;

    userName.textContent = user.name || "Unknown User";
    userEmail.textContent = user.email || "No email";
    if (user.photo) userPhoto.src = user.photo;

    historyTable.innerHTML = "";
    if (!history || history.length === 0) {
      historyTable.innerHTML = `<tr><td colspan="4" style="text-align:center;">No records found</td></tr>`;
    } else {
      history.forEach(r => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${r.type}</td>
          <td>${r.input}</td>
          <td class="${r.status === 'Secure' ? 'status-secure' : 'status-phishing'}">${r.status}</td>
          <td>${new Date(r.created_at).toLocaleString()}</td>
        `;
        historyTable.appendChild(row);
      });
    }
  } catch (err) {
    console.error("Error fetching profile data", err);
    alert("Failed to load profile");
  }
  
  logoutBtn.addEventListener("click", async () => {
    try {
      const res = await fetch("/api/user/logout", {
        method: "POST",
        credentials: "include",
      });
      const data = await res.json();
      if (res.ok) {
        alert(data.message);
        localStorage.removeItem("isLoggedIn");
        localStorage.removeItem("userEmail");
        window.location.href = "/login";
      }
    } catch (err) {
      alert("Server error: " + err.message);
    }
  });
});

const mainUploadBtn = document.getElementById("mainUploadBtn");
const confirmUploadBtn = document.getElementById("confirmUploadBtn");
const fileInput = document.getElementById("fileInput");
const uploadForm = document.getElementById("uploadForm");

mainUploadBtn.addEventListener("click", () => {
  fileInput.click();
});

fileInput.addEventListener("change", () => {
  if (fileInput.files.length > 0) {
    confirmUploadBtn.style.display = "inline-block";
  }
});

uploadForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (fileInput.files.length === 0) {
    alert("Please choose an image first!");
    return;
  }

  const formData = new FormData();
  formData.append("profileImage", fileInput.files[0]);

  try {
    const res = await fetch("/api/user/upload_profile", {
      method: "POST",
      body: formData,
      credentials: "include",
    });
    const data = await res.json();

    if (res.ok) {
      alert("Profile photo updated!");
      document.getElementById("userPhoto").src = data.image_url;

      confirmUploadBtn.style.display = "none";
      fileInput.value = "";
      mainUploadBtn.textContent = "Update Image"; 
    } else {
      alert(data.error || "Upload failed");
    }
  } catch (err) {
    console.error("Upload error:", err);
    alert("Server error during upload");
  }
});
