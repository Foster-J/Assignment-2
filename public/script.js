// Add this to your public/script.js file
document.addEventListener("DOMContentLoaded", function () {
    // Show emoji picker when the "plus" icon is clicked
    const reactionBtns = document.querySelectorAll(".reaction-btn");
    reactionBtns.forEach(btn => {
        btn.addEventListener("click", function () {
            const messageId = btn.getAttribute("data-message-id");
            const emojiPicker = document.getElementById(`emoji-picker-${messageId}`);
            emojiPicker.style.display = emojiPicker.style.display === "none" ? "block" : "none";
        });
    });

    // Add emoji to the message when clicked
    const emojiImages = document.querySelectorAll(".emoji-picker img");
    emojiImages.forEach(img => {
        img.addEventListener("click", function () {
            const emoji = img.getAttribute("data-emoji");
            const messageId = img.closest(".message-container").querySelector(".reaction-btn").getAttribute("data-message-id");

            // Submit emoji reaction via AJAX or form
            addReaction(messageId, emoji);
        });
    });
});

function addReaction(messageId, emoji) {
    fetch(`/addReaction/${messageId}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ emoji: emoji }),
    })
    .then(response => response.json())
    .then(data => {
        // Update the reactions without reloading the page
        const reactionsDiv = document.querySelector(`#message-${messageId} .reactions`);
        reactionsDiv.innerHTML += `<img src="/emojis/${emoji}.png" class="emoji-image" alt="${emoji}">`;
    })
    .catch(error => {
        console.error("Error adding reaction:", error);
    });
}
