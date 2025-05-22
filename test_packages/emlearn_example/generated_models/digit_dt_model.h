


    // !!! This file is generated using emlearn !!!

    #include <eml_trees.h>
    

static const EmlTreesNode digit_dt_nodes[87] = {
  { 36, 0.500000f, 1, 13 },
  { 42, 7.500000f, 1, 6 },
  { 21, 7.000000f, 1, 3 },
  { 28, 5.500000f, 1, -1 },
  { 27, 5.500000f, -2, -3 },
  { 60, 2.000000f, -1, 1 },
  { 9, 10.500000f, -4, -5 },
  { 21, 0.500000f, 1, 4 },
  { 3, 4.500000f, -6, 1 },
  { 45, 1.000000f, 1, -7 },
  { 35, 10.500000f, -1, -3 },
  { 28, 4.500000f, -2, 1 },
  { 59, 14.000000f, -7, -8 },
  { 26, 9.500000f, 1, 32 },
  { 53, 0.500000f, 1, 9 },
  { 19, 10.500000f, 1, 5 },
  { 37, 0.500000f, 1, 2 },
  { 10, 10.500000f, -5, -8 },
  { 60, 12.000000f, -9, 1 },
  { 3, 10.500000f, -5, -4 },
  { 2, 5.500000f, -10, 1 },
  { 20, 10.000000f, -1, 1 },
  { 52, 8.500000f, -9, -8 },
  { 43, 1.500000f, 1, 11 },
  { 29, 13.500000f, 1, 6 },
  { 34, 9.000000f, 1, 4 },
  { 19, 13.500000f, 1, 2 },
  { 62, 14.000000f, -5, -3 },
  { 54, 1.000000f, -5, -10 },
  { 28, 9.500000f, -5, -8 },
  { 3, 3.500000f, -10, 1 },
  { 26, 1.000000f, 1, 2 },
  { 20, 0.500000f, -3, -5 },
  { 18, 2.500000f, -9, -4 },
  { 27, 9.500000f, 1, 6 },
  { 38, 0.500000f, 1, 3 },
  { 20, 0.500000f, -7, 1 },
  { 50, 0.500000f, -10, -3 },
  { 61, 3.500000f, -9, 1 },
  { 18, 11.000000f, -7, -5 },
  { 36, 9.500000f, 1, 2 },
  { 50, 5.000000f, -5, -3 },
  { 44, 14.500000f, 1, 2 },
  { 21, 4.500000f, -7, -8 },
  { 41, 6.500000f, -10, -6 },
  { 21, 0.500000f, 1, 16 },
  { 42, 8.500000f, 1, 9 },
  { 5, 1.500000f, 1, 4 },
  { 62, 14.500000f, 1, -10 },
  { 34, 10.000000f, 1, -6 },
  { 27, 6.500000f, -3, -5 },
  { 18, 4.500000f, 1, 2 },
  { 1, 0.500000f, -6, -5 },
  { 9, 14.500000f, 1, -8 },
  { 24, 0.500000f, -1, -6 },
  { 54, 1.500000f, 1, -7 },
  { 37, 5.500000f, 1, 3 },
  { 12, 13.500000f, 1, -10 },
  { 61, 4.000000f, -6, -7 },
  { 44, 7.500000f, -1, 1 },
  { 33, 2.500000f, -7, -6 },
  { 33, 3.500000f, 1, 15 },
  { 20, 15.500000f, 1, 8 },
  { 43, 3.500000f, 1, 4 },
  { 28, 6.000000f, 1, 2 },
  { 14, 6.000000f, -8, -9 },
  { 42, 9.000000f, -4, -8 },
  { 60, 7.500000f, 1, 2 },
  { 4, 7.500000f, -6, -9 },
  { 21, 4.500000f, -10, -8 },
  { 9, 0.500000f, 1, 4 },
  { 52, 3.000000f, 1, 2 },
  { 34, 2.000000f, -4, -9 },
  { 28, 7.000000f, -10, -10 },
  { 38, 2.500000f, 1, -4 },
  { 59, 15.500000f, -5, -3 },
  { 27, 14.500000f, 1, 6 },
  { 13, 14.000000f, 1, 3 },
  { 5, 12.000000f, -6, 1 },
  { 25, 3.500000f, -9, -4 },
  { 36, 6.000000f, -2, 1 },
  { 27, 7.500000f, -6, -7 },
  { 38, 1.000000f, 1, 2 },
  { 12, 8.000000f, -8, -10 },
  { 45, 13.000000f, 1, 2 },
  { 30, 12.000000f, -6, -9 },
  { 2, 3.500000f, -10, -7 } 
};

static const int32_t digit_dt_tree_roots[1] = { 0 };

static const uint8_t digit_dt_leaves[10] = { 5, 0, 2, 9, 3, 4, 6, 8, 7, 1 };

EmlTrees digit_dt = {
        87,
        (EmlTreesNode *)(digit_dt_nodes),	  
        1,
        (int32_t *)(digit_dt_tree_roots),
        10,
        (uint8_t *)(digit_dt_leaves),
        0,
        64,
        10,
    };

static inline int32_t digit_dt_tree_0(const float *features, int32_t features_length) {
          if (features[36] < 0.500000f) {
              if (features[42] < 7.500000f) {
                  if (features[21] < 7.000000f) {
                      if (features[28] < 5.500000f) {
                          if (features[27] < 5.500000f) {
                              return 0;
                          } else {
                              return 2;
                          }
                      } else {
                          return 5;
                      }
                  } else {
                      if (features[60] < 2.000000f) {
                          return 5;
                      } else {
                          if (features[9] < 10.500000f) {
                              return 9;
                          } else {
                              return 3;
                          }
                      }
                  }
              } else {
                  if (features[21] < 0.500000f) {
                      if (features[3] < 4.500000f) {
                          return 4;
                      } else {
                          if (features[45] < 1.000000f) {
                              if (features[35] < 10.500000f) {
                                  return 5;
                              } else {
                                  return 2;
                              }
                          } else {
                              return 6;
                          }
                      }
                  } else {
                      if (features[28] < 4.500000f) {
                          return 0;
                      } else {
                          if (features[59] < 14.000000f) {
                              return 6;
                          } else {
                              return 8;
                          }
                      }
                  }
              }
          } else {
              if (features[26] < 9.500000f) {
                  if (features[53] < 0.500000f) {
                      if (features[19] < 10.500000f) {
                          if (features[37] < 0.500000f) {
                              if (features[10] < 10.500000f) {
                                  return 3;
                              } else {
                                  return 8;
                              }
                          } else {
                              if (features[60] < 12.000000f) {
                                  return 7;
                              } else {
                                  if (features[3] < 10.500000f) {
                                      return 3;
                                  } else {
                                      return 9;
                                  }
                              }
                          }
                      } else {
                          if (features[2] < 5.500000f) {
                              return 1;
                          } else {
                              if (features[20] < 10.000000f) {
                                  return 5;
                              } else {
                                  if (features[52] < 8.500000f) {
                                      return 7;
                                  } else {
                                      return 8;
                                  }
                              }
                          }
                      }
                  } else {
                      if (features[43] < 1.500000f) {
                          if (features[29] < 13.500000f) {
                              if (features[34] < 9.000000f) {
                                  if (features[19] < 13.500000f) {
                                      if (features[62] < 14.000000f) {
                                          return 3;
                                      } else {
                                          return 2;
                                      }
                                  } else {
                                      if (features[54] < 1.000000f) {
                                          return 3;
                                      } else {
                                          return 1;
                                      }
                                  }
                              } else {
                                  if (features[28] < 9.500000f) {
                                      return 3;
                                  } else {
                                      return 8;
                                  }
                              }
                          } else {
                              if (features[3] < 3.500000f) {
                                  return 1;
                              } else {
                                  if (features[26] < 1.000000f) {
                                      if (features[20] < 0.500000f) {
                                          return 2;
                                      } else {
                                          return 3;
                                      }
                                  } else {
                                      if (features[18] < 2.500000f) {
                                          return 7;
                                      } else {
                                          return 9;
                                      }
                                  }
                              }
                          }
                      } else {
                          if (features[27] < 9.500000f) {
                              if (features[38] < 0.500000f) {
                                  if (features[20] < 0.500000f) {
                                      return 6;
                                  } else {
                                      if (features[50] < 0.500000f) {
                                          return 1;
                                      } else {
                                          return 2;
                                      }
                                  }
                              } else {
                                  if (features[61] < 3.500000f) {
                                      return 7;
                                  } else {
                                      if (features[18] < 11.000000f) {
                                          return 6;
                                      } else {
                                          return 3;
                                      }
                                  }
                              }
                          } else {
                              if (features[36] < 9.500000f) {
                                  if (features[50] < 5.000000f) {
                                      return 3;
                                  } else {
                                      return 2;
                                  }
                              } else {
                                  if (features[44] < 14.500000f) {
                                      if (features[21] < 4.500000f) {
                                          return 6;
                                      } else {
                                          return 8;
                                      }
                                  } else {
                                      if (features[41] < 6.500000f) {
                                          return 1;
                                      } else {
                                          return 4;
                                      }
                                  }
                              }
                          }
                      }
                  }
              } else {
                  if (features[21] < 0.500000f) {
                      if (features[42] < 8.500000f) {
                          if (features[5] < 1.500000f) {
                              if (features[62] < 14.500000f) {
                                  if (features[34] < 10.000000f) {
                                      if (features[27] < 6.500000f) {
                                          return 2;
                                      } else {
                                          return 3;
                                      }
                                  } else {
                                      return 4;
                                  }
                              } else {
                                  return 1;
                              }
                          } else {
                              if (features[18] < 4.500000f) {
                                  if (features[1] < 0.500000f) {
                                      return 4;
                                  } else {
                                      return 3;
                                  }
                              } else {
                                  if (features[9] < 14.500000f) {
                                      if (features[24] < 0.500000f) {
                                          return 5;
                                      } else {
                                          return 4;
                                      }
                                  } else {
                                      return 8;
                                  }
                              }
                          }
                      } else {
                          if (features[54] < 1.500000f) {
                              if (features[37] < 5.500000f) {
                                  if (features[12] < 13.500000f) {
                                      if (features[61] < 4.000000f) {
                                          return 4;
                                      } else {
                                          return 6;
                                      }
                                  } else {
                                      return 1;
                                  }
                              } else {
                                  if (features[44] < 7.500000f) {
                                      return 5;
                                  } else {
                                      if (features[33] < 2.500000f) {
                                          return 6;
                                      } else {
                                          return 4;
                                      }
                                  }
                              }
                          } else {
                              return 6;
                          }
                      }
                  } else {
                      if (features[33] < 3.500000f) {
                          if (features[20] < 15.500000f) {
                              if (features[43] < 3.500000f) {
                                  if (features[28] < 6.000000f) {
                                      if (features[14] < 6.000000f) {
                                          return 8;
                                      } else {
                                          return 7;
                                      }
                                  } else {
                                      if (features[42] < 9.000000f) {
                                          return 9;
                                      } else {
                                          return 8;
                                      }
                                  }
                              } else {
                                  if (features[60] < 7.500000f) {
                                      if (features[4] < 7.500000f) {
                                          return 4;
                                      } else {
                                          return 7;
                                      }
                                  } else {
                                      if (features[21] < 4.500000f) {
                                          return 1;
                                      } else {
                                          return 8;
                                      }
                                  }
                              }
                          } else {
                              if (features[9] < 0.500000f) {
                                  if (features[52] < 3.000000f) {
                                      if (features[34] < 2.000000f) {
                                          return 9;
                                      } else {
                                          return 7;
                                      }
                                  } else {
                                      if (features[28] < 7.000000f) {
                                          return 1;
                                      } else {
                                          return 1;
                                      }
                                  }
                              } else {
                                  if (features[38] < 2.500000f) {
                                      if (features[59] < 15.500000f) {
                                          return 3;
                                      } else {
                                          return 2;
                                      }
                                  } else {
                                      return 9;
                                  }
                              }
                          }
                      } else {
                          if (features[27] < 14.500000f) {
                              if (features[13] < 14.000000f) {
                                  if (features[5] < 12.000000f) {
                                      return 4;
                                  } else {
                                      if (features[25] < 3.500000f) {
                                          return 7;
                                      } else {
                                          return 9;
                                      }
                                  }
                              } else {
                                  if (features[36] < 6.000000f) {
                                      return 0;
                                  } else {
                                      if (features[27] < 7.500000f) {
                                          return 4;
                                      } else {
                                          return 6;
                                      }
                                  }
                              }
                          } else {
                              if (features[38] < 1.000000f) {
                                  if (features[12] < 8.000000f) {
                                      return 8;
                                  } else {
                                      return 1;
                                  }
                              } else {
                                  if (features[45] < 13.000000f) {
                                      if (features[30] < 12.000000f) {
                                          return 4;
                                      } else {
                                          return 7;
                                      }
                                  } else {
                                      if (features[2] < 3.500000f) {
                                          return 1;
                                      } else {
                                          return 6;
                                      }
                                  }
                              }
                          }
                      }
                  }
              }
          }
        }
        

int32_t digit_dt_predict(const float *features, int32_t features_length) {

        int32_t votes[10] = {0,};
        int32_t _class = -1;

        _class = digit_dt_tree_0(features, features_length); votes[_class] += 1;
    
        int32_t most_voted_class = -1;
        int32_t most_voted_votes = 0;
        for (int32_t i=0; i<10; i++) {

            if (votes[i] > most_voted_votes) {
                most_voted_class = i;
                most_voted_votes = votes[i];
            }
        }
        return most_voted_class;
    }
    