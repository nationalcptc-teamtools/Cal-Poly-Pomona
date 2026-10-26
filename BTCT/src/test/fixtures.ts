import type { Page } from '@/types';
import { v4 as uuidv4 } from 'uuid';

const now = Date.now();

export const fixturePages: Page[] = [
  {
    id: 'page-1',
    workspaceId: 'ws-1',
    parentId: null,
    title: 'Test Page',
    slug: 'test-page',
    icon: '',
    tags: ['test', 'demo'],
    content: [
      { id: uuidv4(), type: 'heading', props: { level: 2 }, content: [{ type: 'text', text: 'Hello World', styles: {} }], children: [] },
      { id: uuidv4(), type: 'paragraph', content: [{ type: 'text', text: 'This is a test page.', styles: {} }], children: [], props: {} },
      { id: uuidv4(), type: 'bulletListItem', content: [{ type: 'text', text: 'Item one', styles: {} }], children: [], props: {} },
      { id: uuidv4(), type: 'bulletListItem', content: [{ type: 'text', text: 'Bold item', styles: { bold: true } }], children: [], props: {} },
    ],
    sortOrder: 0,
    isGraphPage: false,
    createdAt: now,
    updatedAt: now,
  },
  {
    id: 'page-2',
    workspaceId: 'ws-1',
    parentId: null,
    title: 'Node Page',
    slug: 'node-page',
    icon: '',
    tags: [],
    content: [
      { id: uuidv4(), type: 'paragraph', content: [{ type: 'text', text: 'Linked from a graph node.', styles: {} }], children: [], props: {} },
    ],
    sortOrder: 1,
    isGraphPage: true,
    createdAt: now,
    updatedAt: now,
  },
];
