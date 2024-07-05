document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('expense-form');
  const expensesList = document.getElementById('expenses-list');

  // Fetch all expenses
  const fetchExpenses = async () => {
    try {
      const response = await fetch('http://localhost:5000/expenses');
      const expenses = await response.json();
      expensesList.innerHTML = '';
      expenses.forEach((expense) => {
        const listItem = document.createElement('tr');
        listItem.innerHTML = `
          <td>${expense.name}</td>
          <td>$${expense.amount.toFixed(2)}</td>
          <td>${new Date(expense.date_created).toLocaleDateString()}</td>
          <td>
            <button class="delete-btn" data-id="${expense._id}">Delete</button>
            <button class="edit-btn" data-id="${expense._id}">Edit</button>
          </td>
        `;
        expensesList.appendChild(listItem);
      });
    } catch (err) {
      console.error(err);
    }
  };

  // Add expense
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(form);
    const name = formData.get('name');
    const amount = parseFloat(formData.get('amount'));

    try {
      await fetch('http://localhost:5000/expenses', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, amount }),
      });
      form.reset();
      fetchExpenses();
    } catch (err) {
      console.error(err);
    }
  });

  // Delete and edit expense (event delegation)
  expensesList.addEventListener('click', async (e) => {
    if (e.target.classList.contains('delete-btn')) {
      const id = e.target.getAttribute('data-id');
      try {
        await fetch(`http://localhost:5000/expenses/${id}`, {
          method: 'DELETE',
        });
        fetchExpenses();
      } catch (err) {
        console.error(err);
      }
    }
    // Add edit logic here (omitted for brevity)
  });

  fetchExpenses();
});

document.addEventListener('DOMContentLoaded', () => {
  const signupForm = document.getElementById('signup-form');
  const loginForm = document.getElementById('login-form');

  // Handle signup
  signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(signupForm);
    const username = formData.get('username');
    const password = formData.get('password');

    try {
      const response = await fetch('http://localhost:5000/auth/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      const result = await response.json();
      if (response.ok) {
        alert('Signup successful!');
        window.location.href = '/login';
      } else {
        alert(result.message);
      }
    } catch (err) {
      console.error(err);
    }
  });

  // Handle login
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(loginForm);
    const username = formData.get('username');
    const password = formData.get('password');

    try {
      const response = await fetch('http://localhost:5000/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      const result = await response.json();
      if (response.ok) {
        localStorage.setItem('token', result.token);
        alert('Login successful!');
        window.location.href = '/';
      } else {
        alert(result.message);
      }
    } catch (err) {
      console.error(err);
    }
  });
});
