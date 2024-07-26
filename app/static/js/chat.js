document.addEventListener("DOMContentLoaded", function () {
  document.getElementById("sendButton").addEventListener("click", sendMessage);
  document.getElementById("clearButton").addEventListener("click", clearChat);
  loadChatHistory();
});

async function loadChatHistory() {
  const response = await fetch("/chat/history", {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
  });

  const data = await response.json();
  const messagesDiv = document.getElementById("messages");

  if (data.messages) {
    data.messages.forEach((message) => {
      const messageDiv = document.createElement("div");
      messageDiv.innerHTML = `${
        message.role === "user" ? "Você" : "<b>Assistente</b>"
      }: ${message.content}`;
      messagesDiv.appendChild(messageDiv);
    });
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }

}

async function sendMessage(event) {
  event.preventDefault(); // Prevenir a submissão do formulário
  const userInput = document.getElementById("userInput").value;
  const messagesDiv = document.getElementById("messages");
  const csrfToken = document.querySelector('input[name="csrf_token"]').value;

  // Exibindo a mensagem do usuário
  const userMessageDiv = document.createElement("div");
  userMessageDiv.textContent = `Você: ${userInput}`;
  messagesDiv.appendChild(userMessageDiv);
  document.getElementById("userInput").value = "";
  // Enviando a mensagem para o backend
  const response = await fetch("/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": csrfToken,
    },
    body: JSON.stringify({ message: userInput }),
  });
  // Limpando o campo de entrada

  const data = await response.json();

  if (data.error) {
    alert(data.error);
  } else {
    // Exibindo a resposta do bot
    const botMessageDiv = document.createElement("div");
    botMessageDiv.textContent = `Assistente: ${data.response}`;
    messagesDiv.appendChild(botMessageDiv);

    // Rolando para a última mensagem
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }
}

async function clearChat() {
  const csrfToken = document.querySelector('input[name="csrf_token"]').value;

  const response = await fetch("/chat/clear", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": csrfToken,
    },
  });

  const data = await response.json();

  if (data.message) {
    const messagesDiv = document.getElementById("messages");
    messagesDiv.innerHTML = ""; // Limpa o conteúdo do chatbox
    alert(data.message); // Exibe uma mensagem de confirmação
  } else {
    alert("Erro ao limpar o chat");
  }
}
