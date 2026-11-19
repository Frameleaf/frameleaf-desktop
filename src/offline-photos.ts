import { mount } from 'svelte';
import './style.css';
import OfflinePhotos from './OfflinePhotos.svelte';

mount(OfflinePhotos, { target: document.getElementById('app')! });
