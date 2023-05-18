import React, { useState } from 'react';
import Sidebar from '../Sidebar/Sidebar.jsx';
import styles from './MainContainer.module.scss';
import Login from '../../components/userStart/Login.jsx';
import Signup from '../../components/userStart/Signup.jsx';
import validator from 'validator';
const MainContainer = () => {
  const [login, setLogin] = useState(false);
  const [haveAccount, setHaveAccount] = useState(true);

  const [strengthMessage, setStrengthMessage] = useState('');
  
  //MAY NEED TO REMOVE -- DUPLICATE WITH STRENGTHMESSAGE
  const [error, setError] = useState(false);


  const handleLogin = (e) => {
    e.preventDefault();
    const usernameInputValue = document.getElementById('username').value;
    document.getElementById('username').value = '';
    const passwordInputValue = document.getElementById('password').value;
    document.getElementById('password').value = '';

    if(usernameInputValue === '' ||  passwordInputValue === ''){
      document.querySelector('.errorMessage').innerHTML = ' Username and password are required';
      return false;
    };

   

    fetch('http://localhost:3000/authentication/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      // include cookies from cross origin request
      credentials: 'include',
      body: JSON.stringify({
        username: usernameInputValue,
        password: passwordInputValue,
      }),
    })
      .then((result) => result.json())
      .then((result) => {
        console.log('result from login request: ', result);
        setLogin(result.username);
      })
      .catch((err) => {
      
      //MAY NEED TO REMOVE -- SEE IF TWO MESSAGES APPEAR
       setError(true);
        console.log(err);


        document.querySelector('.errorMessage').innerHTML = 'Please verify your user information and try again!';
        return false;
       
      });
  };
  //functino to handle showing the signup page
  const handleHaveAccount = () => setHaveAccount(false);

  //function to handle password strength check
  const handleStrength = (input) => {
    if(validator.isStrongPassword(input, {
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1
    })){
      setStrengthMessage('Strong Password');
    } else {
      setStrengthMessage('Not A Strong Password');
    }
  };

  //function to handle sign-up if username was not already taken
  const handleSigned = (e) => {
    e.preventDefault();
    const nameValue = document.getElementById('user').value;
    document.getElementById('user').value = '';
    const passwordValue = document.getElementById('psw').value;
    document.getElementById('psw').value = '';

    fetch('http://localhost:3000/authentication/signup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: nameValue,
        password: passwordValue,
      }),
    })
      .then((result) => result.json())
      .then((result) => {
        console.log('result from signup request: ', result);
        setHaveAccount(true);
        setLogin(result.username);
      })
      .catch((err) => {
        console.log(err);
      });
  };

  return login ? (

    <div className={styles.container}>
      <div className={styles.div}>
        <button
          className={styles.button}
          onClick={() => {
            setLogin(false);
          }}>
          Logout
        </button>
        <h2 className={styles.h2}>
          welcome, <span className={styles.span}>{login}</span>
        </h2>
      </div>
      <Sidebar />
    </div>
  ) : haveAccount ? (
    <div className={styles.container}>
      <Login
        handleLogin={handleLogin}
        handleHaveAccount={handleHaveAccount}
        style={`${error ? 'red' : ''}`}
        error={error}
      />

    </div>
  ) : (
    <div className={styles.container}>
      <Signup handleSigned={ handleSigned } strengthMessage={ strengthMessage } handleStrength={ handleStrength }/>
    </div>
  );
};

export default MainContainer;
