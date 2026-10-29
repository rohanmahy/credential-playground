import { mount } from 'svelte';
import App from './App.svelte';
import './app.css';
import { createAppContext } from './lib/context';
import { selectEngine } from './lib/engine/select';
import { selectPlatform } from './lib/platform/select';

const target = document.getElementById('app');
if (!target) throw new Error('#app missing');

const engine = await selectEngine();
const platform = selectPlatform();
mount(App, { target, props: { ctx: createAppContext(engine, platform) } });
