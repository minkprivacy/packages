import type { LightWasm } from '@lightprotocol/hasher.rs';

export const DEFAULT_ZERO = 0;

/**
 * Merkle tree implementation for privacy transactions
 * Uses Poseidon hash function via @lightprotocol/hasher.rs
 */
export class MerkleTree {
  levels: number;
  capacity: number;
  zeroElement: string;
  private _zeros: string[];
  private _layers: string[][];
  private _lightWasm: LightWasm;

  constructor(
    levels: number,
    lightWasm: LightWasm,
    elements: string[] = [],
    { zeroElement = DEFAULT_ZERO } = {},
  ) {
    this.levels = levels;
    this.capacity = 2 ** levels;
    this.zeroElement = zeroElement.toString();
    this._lightWasm = lightWasm;

    if (elements.length > this.capacity) {
      throw new Error('Tree is full');
    }

    this._zeros = [];
    this._layers = [];
    this._layers[0] = elements;
    this._zeros[0] = this.zeroElement;

    // Pre-compute zero values for each level
    for (let i = 1; i <= levels; i++) {
      this._zeros[i] = this._lightWasm.poseidonHashString([
        this._zeros[i - 1],
        this._zeros[i - 1],
      ]);
    }

    this._rebuild();
  }

  private _rebuild(): void {
    for (let level = 1; level <= this.levels; level++) {
      this._layers[level] = [];
      for (let i = 0; i < Math.ceil(this._layers[level - 1].length / 2); i++) {
        this._layers[level][i] = this._lightWasm.poseidonHashString([
          this._layers[level - 1][i * 2],
          i * 2 + 1 < this._layers[level - 1].length
            ? this._layers[level - 1][i * 2 + 1]
            : this._zeros[level - 1],
        ]);
      }
    }
  }

  /**
   * Get tree root
   */
  root(): string {
    return this._layers[this.levels].length > 0
      ? this._layers[this.levels][0]
      : this._zeros[this.levels];
  }

  /**
   * Insert new element into the tree
   */
  insert(element: string): void {
    if (this._layers[0].length >= this.capacity) {
      throw new Error('Tree is full');
    }
    this.update(this._layers[0].length, element);
  }

  /**
   * Insert multiple elements into the tree
   */
  bulkInsert(elements: string[]): void {
    if (this._layers[0].length + elements.length > this.capacity) {
      throw new Error('Tree is full');
    }
    this._layers[0].push(...elements);
    this._rebuild();
  }

  /**
   * Change an element in the tree
   */
  update(index: number, element: string): void {
    if (
      isNaN(Number(index)) ||
      index < 0 ||
      index > this._layers[0].length ||
      index >= this.capacity
    ) {
      throw new Error('Insert index out of bounds: ' + index);
    }

    this._layers[0][index] = element;

    for (let level = 1; level <= this.levels; level++) {
      index >>= 1;
      this._layers[level][index] = this._lightWasm.poseidonHashString([
        this._layers[level - 1][index * 2],
        index * 2 + 1 < this._layers[level - 1].length
          ? this._layers[level - 1][index * 2 + 1]
          : this._zeros[level - 1],
      ]);
    }
  }

  /**
   * Get merkle path to a leaf
   */
  path(index: number): { pathElements: string[]; pathIndices: number[] } {
    if (isNaN(Number(index)) || index < 0 || index >= this._layers[0].length) {
      throw new Error('Index out of bounds: ' + index);
    }

    const pathElements: string[] = [];
    const pathIndices: number[] = [];

    for (let level = 0; level < this.levels; level++) {
      pathIndices[level] = index % 2;
      pathElements[level] =
        (index ^ 1) < this._layers[level].length
          ? this._layers[level][index ^ 1]
          : this._zeros[level];
      index >>= 1;
    }

    return { pathElements, pathIndices };
  }

  /**
   * Find an element in the tree
   */
  indexOf(element: string, comparator?: (a: string, b: string) => boolean): number {
    if (comparator) {
      return this._layers[0].findIndex((el: string) => comparator(element, el));
    }
    return this._layers[0].indexOf(element);
  }

  /**
   * Returns a copy of non-zero tree elements
   */
  elements(): string[] {
    return this._layers[0].slice();
  }

  /**
   * Serialize tree state
   */
  serialize(): { levels: number; _zeros: string[]; _layers: string[][] } {
    return {
      levels: this.levels,
      _zeros: this._zeros,
      _layers: this._layers,
    };
  }

  /**
   * Deserialize data into a MerkleTree instance
   */
  static deserialize(
    data: { levels: number; _zeros: string[]; _layers: string[][] },
    lightWasm: LightWasm
  ): MerkleTree {
    const instance = new MerkleTree(data.levels, lightWasm);
    instance._zeros = data._zeros;
    instance._layers = data._layers;
    return instance;
  }
}
