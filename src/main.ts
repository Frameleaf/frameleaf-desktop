import { mount } from 'svelte';
import App from './App.svelte';
import './style.css';
import { platformClass } from './ui-state';
document.documentElement.classList.add(platformClass(navigator.userAgent));
mount(App, { target: document.getElementById('app')! });
