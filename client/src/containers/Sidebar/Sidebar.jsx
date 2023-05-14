import React, { useState, useEffect } from 'react';
import SnippetDisplay from '../../components/SnippetDisplay/SnippetDisplay.jsx';
import AddSnippet from '../../components/AddSnippet/AddSnippet.jsx';

const Sidebar = () => {
  const [state, setState] = useState({
    snippets: [],
    selectedSnippet: {
      id: '',
      title: '',
      comments: '',
      storedCode: '',
      tags: [],
      language: '',
    },
  });

  // set up getSnippet func
  // send get request to server
  // setState with data

  const [openModal, setOpenModal] = useState(false);

  return (
    <div className="sidebar">
      <h1>Sidebar</h1>
      <SnippetDisplay />
      <button className="addButton" onClick={() => {setOpenModal(true)}}>
        Add a snippet
      </button>
      {openModal && <AddSnippet closeModal={setOpenModal}/>}
    </div>
  );
};

export default Sidebar;
